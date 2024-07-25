use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use chrono::Utc;
use hex;
use notatin::{parser::Parser, cell_value::CellValue, util::get_date_time_from_filetime};
use std::ffi::CString;
use windows::Win32::Foundation::NTSTATUS;

// Get local account informations
// Reference: https://github.com/C-Sto/gosecretsdump/blob/master/pkg/samreader/samreader.go


#[link(name = "ntdll.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    pub fn SystemFunction027(EncryptedNtOwfPassword: *mut i8, Index: *mut u32, NtOwfPassword: *mut i8) -> NTSTATUS;
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct SAMHash {
    pekid: u16,
    revision: u16,
    data: [u8; 0x34]
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct SAMEntry {
    offset: u32,
    length: u32,
    unknown: u32
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct FDATA {
    revision: u16,
    unknown1: u32,
    unknown2: u16,
    last_password_set_time: u64,
    domain_modified_count: u64,
    max_password_age: u64,
    min_password_age: u64,
    force_logoff: u64,
    lockout_duration: u64,
    lockout_observation_window: u64,
    modified_count_at_last_promotion: u64,
    next_rid: u32,
    password_properties: u32,
    min_password_length: u16,
    password_history_length: u16,
    lockout_threshold: u16,
    unknown3: u16,
    server_state: u32,
    server_role: u32,
    uas_compatibility_required: u32,
    unknown4: u32,
    data: [u8; 64]
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct FUSERDATA {
    unknown1: u64,
    last_logon_time: u64,
    unknown2: u64,
    last_password_set_time: u64,
    unknown3: u64,
    last_incorrect_password_time: u64
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct VDATA {
    unknown1: SAMEntry,
	username: SAMEntry, 
    fullname: SAMEntry, 
    comment: SAMEntry,
	user_comment: SAMEntry,
	unknown2: SAMEntry,
	homedir: SAMEntry,
	homedir_connect: SAMEntry,
	script_path: SAMEntry,
	profile_path: SAMEntry,
	workstations: SAMEntry,
	hours_allowed: SAMEntry,
	unknown3: SAMEntry,
	lm_hash: SAMEntry,
	ntlm_hash: SAMEntry,
	ntlm_history: SAMEntry,
	lm_history: SAMEntry
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct SamKeyDataAes {
    revision: u32,
    length: u32,
    checklen: u32,
    datalen: u32,
    salt: [u8; 16],
    data: [u8; 32]
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
struct SamHashAes {
    pekid: u16,
    revision: u16,
    data_offset: u32,
    salt: [u8; 16],
    data: [u8; 32]
}

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::core::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::core::mem::size_of::<T>(),
    )
}

// ref: https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_lsadump.c#L412
fn get_ntlm_hash(sam_entry: SAMEntry, hash: SAMHash, syskey: Vec<u8>, mut rid: u32) -> Vec<String> {
    let mut hashes: Vec<String> = Vec::new();

    let t = &syskey;
    let syskey_array: &[u8] = &t;
    let mut plaintext: Vec<u8> = Vec::new();

    if sam_entry.offset != 0 && sam_entry.length != 0 {
        let r = hash.revision;

        match r {
            1 => {
                println!("[-] Currently, SAMHash revision {} is not supported", r);
                return hashes;
            },
            2 => {
                let hash_bytes = unsafe { any_as_u8_slice(&hash).to_vec() };
                let hash_aes: SamHashAes = unsafe { std::ptr::read(hash_bytes.as_ptr() as *const _) };

                if hash_aes.data_offset >= 16 {
                    let decryptor = Aes128CbcDec::new(syskey_array.into(), &hash_aes.salt.into());
                    plaintext = decryptor
                        .decrypt_padded_vec_mut::<Pkcs7>(&hash_aes.data)
                        .unwrap();
                } else {
                    return hashes;
                }
            },
            _ => {
                println!("[-] Unknown SAMHash revision: {}", r);
                return hashes;
            }
        }
    } else {
        return hashes;
    }

    let ntlm_hash = CString::new("0000000000000000").unwrap().into_raw();
    for i in (0..plaintext.len()).step_by(16) {
        unsafe {
            let original_data = CString::new(plaintext.clone()).unwrap().into_raw().wrapping_add(i);
            if SystemFunction027(original_data, &mut rid, ntlm_hash).is_ok() {
                let ntlm_hash_str = hex::encode(CString::from_raw(ntlm_hash).as_bytes());
                hashes.push(ntlm_hash_str);
            } else {
                println!("[-] SystemFunction027 failed")
            }
        }
    }

    return hashes;
}

pub fn get_syskey(parser: &mut Parser, bootkey: [u8; 16]) ->  Option<Vec<u8>> {
    let key_path = "SAM\\Domains\\Account";
    let akey = parser.get_key(&key_path, false).unwrap().unwrap();

    match akey.get_value("F").unwrap().get_content().0 {
        CellValue::Binary(f) => {
            let fdata: FDATA = unsafe { std::ptr::read(f.as_ptr() as *const _) };
            let r = fdata.revision;
            let d = fdata.data;
            if r == 3 {
                let aes_struct: SamKeyDataAes = unsafe { std::ptr::read(d.as_ptr() as *const _) };
                let decryptor = Aes128CbcDec::new(&bootkey.into(), &aes_struct.salt.into());
                let plaintext = decryptor
                .decrypt_padded_vec_mut::<Pkcs7>(&aes_struct.data)
                .unwrap();
                return Some(plaintext);
            } else {
                println!("[-] Revision {} is not yet supported!", r);
            }
        },
        _ => {
            println!("[-] Failed to read value F under Domains\\Account key");
        }
    }
    None
}

pub fn get_rids(parser: &mut Parser) -> Vec<String> {
    let mut rids: Vec<String> = Vec::new();
    let key_path = "SAM\\Domains\\Account\\Users";
    let mut akey = parser.get_key(&key_path, false).unwrap().unwrap();

    for skey in akey.read_sub_keys(parser) {
        if skey.key_name != "Names" {
            rids.push(skey.key_name);
        }
    }

    rids
}

pub fn get_account_info(parser: &mut Parser, rid: String, syskey: Vec<u8>) -> Option<String> {
    let mut results: Vec<String> = Vec::new();

    let key_path = format!("SAM\\Domains\\Account\\Users\\{}", rid);
    let akey = parser.get_key(&key_path, false).unwrap().unwrap();
    let rid_num = u32::from_be_bytes(hex::decode(rid).unwrap().try_into().unwrap());

    let mut reset_data = String::new();

    let mut last_logon_time = Utc::now();
    let mut last_password_set_time = Utc::now();
    let mut last_incorrect_password_time = Utc::now();

    match akey.get_value("ResetData") {
        Some(v) => {
            match v.get_content().0 {
                CellValue::Binary(f) => {
                    let reset_data_packets = f
                        .chunks(2)
                        .map(|e| u16::from_le_bytes(e.try_into().unwrap()))
                        .collect::<Vec<_>>();
                    reset_data = String::from_utf16_lossy(&reset_data_packets);
                },
                _ => {
                    println!("[-] Failed to read value ResetData under Domains\\Account key");
                }
            }
        },
        None => {}
    }

    match akey.get_value("F").unwrap().get_content().0 {
        CellValue::Binary(f) => {
            let fuserdata: FUSERDATA = unsafe { std::ptr::read(f.as_ptr() as *const _) };
            last_logon_time = get_date_time_from_filetime(fuserdata.last_logon_time);
            last_password_set_time = get_date_time_from_filetime(fuserdata.last_password_set_time);
            last_incorrect_password_time = get_date_time_from_filetime(fuserdata.last_incorrect_password_time);
        },
        _ => {
            println!("[-] Failed to read value F under Domains\\Account key");
        }
    }

    match akey.get_value("V").unwrap().get_content().0 {
        CellValue::Binary(v) => {
            let vdata: VDATA = unsafe { std::ptr::read(v.as_ptr() as *const _) };
            let idata = v[204..].to_vec();

            // Get LM hash
            let mut start_offset = vdata.lm_hash.offset as usize;
            let mut end_offset = start_offset + vdata.lm_hash.length as usize;
            let mut sam_hash: SAMHash = unsafe { std::ptr::read(idata[start_offset..end_offset].to_vec().as_ptr() as *const _) };
            let lm_hash = get_ntlm_hash(vdata.lm_hash, sam_hash, syskey.clone(), rid_num);

            // Get NTLM hash
            start_offset = vdata.ntlm_hash.offset as usize;
            end_offset = start_offset + vdata.ntlm_hash.length as usize;
            sam_hash = unsafe { std::ptr::read(idata[start_offset..end_offset].to_vec().as_ptr() as *const _) };
            let ntlm_hash = get_ntlm_hash(vdata.ntlm_hash, sam_hash, syskey.clone(), rid_num);

            // Get LM hash history
            start_offset = vdata.lm_history.offset as usize;
            end_offset = start_offset + vdata.lm_history.length as usize;
            sam_hash = unsafe { std::ptr::read(idata[start_offset..end_offset].to_vec().as_ptr() as *const _) };
            let lm_history = get_ntlm_hash(vdata.lm_history, sam_hash, syskey.clone(), rid_num);

            // Get NTLM hash history
            start_offset = vdata.ntlm_history.offset as usize;
            end_offset = start_offset + vdata.ntlm_history.length as usize;
            sam_hash = unsafe { std::ptr::read(idata[start_offset..end_offset].to_vec().as_ptr() as *const _) };
            let ntlm_history = get_ntlm_hash(vdata.ntlm_history, sam_hash, syskey.clone(), rid_num);

            // Get username
            start_offset = vdata.username.offset as usize;
            end_offset = start_offset + vdata.username.length as usize;
            let username_base = idata[start_offset..end_offset].to_vec();
            let username_packets = username_base
                .chunks(2)
                .map(|e| u16::from_le_bytes(e.try_into().unwrap()))
                .collect::<Vec<_>>();
            let username = String::from_utf16_lossy(&username_packets);

            // Get fullname
            start_offset = vdata.fullname.offset as usize;
            end_offset = start_offset + vdata.fullname.length as usize;
            let fullname = String::from_utf8(idata[start_offset..end_offset].to_vec()).unwrap();

            // Get comment
            start_offset = vdata.comment.offset as usize;
            end_offset = start_offset + vdata.comment.length as usize;
            let comment = String::from_utf8(idata[start_offset..end_offset].to_vec()).unwrap();

            // Get user_comment
            start_offset = vdata.user_comment.offset as usize;
            end_offset = start_offset + vdata.user_comment.length as usize;
            let user_comment = String::from_utf8(idata[start_offset..end_offset].to_vec()).unwrap();

            // Get creation time of user
            let creation_time_str = match parser.get_key(&format!("SAM\\Domains\\Account\\Users\\Names\\{}", username), false).unwrap() {
                Some(k) => {
                    format!("{}", get_date_time_from_filetime(k.detail.last_key_written_date_and_time()))
                },
                None => String::from("-")
            };

            results.push(format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}", 
                rid_num, username, creation_time_str, last_logon_time, last_password_set_time, last_incorrect_password_time, fullname, comment, user_comment,
                lm_hash.join(":"), ntlm_hash.join(":"), 
                lm_history.join(", "), ntlm_history.join(", "), 
                reset_data
            ));
        },
        _ => {
            println!("[-] Failed to read value V under Domains\\Account key");
        }
    }

    if results.len() != 0 {
        Some(results.join("\n"))
    } else {
        None
    }
}