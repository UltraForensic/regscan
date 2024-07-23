use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use easydes::easydes::{des_ecb, Des};
use hex;
use notatin::{parser::Parser, cell_value::CellValue};

// Get local account informations
// Reference: https://github.com/C-Sto/gosecretsdump/blob/master/pkg/samreader/samreader.go

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
    creation_time: u64,
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

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

fn transform_key(in_key: [u8; 7]) -> [u8; 8] {
    let mut result: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];

    result[0] = in_key[0] >> 0x01;
    result[1] = ((in_key[0] & 0x01) << 6) | in_key[1] >> 2;
	result[2] = ((in_key[1] & 0x03) << 5) | in_key[2] >> 3;
	result[3] = ((in_key[2] & 0x07) << 4) | in_key[3] >> 4;
	result[4] = ((in_key[3] & 0x0f) << 3) | in_key[4] >> 5;
	result[5] = ((in_key[4] & 0x1f) << 2) | in_key[5] >> 6;
	result[6] = ((in_key[5] & 0x3f) << 1) | in_key[6] >> 7;
	result[7] = in_key[6] & 0x7f;

	for i in 0..8 {
		result[i] = (result[i] << 1) & 0xfe
	}

    result
}

fn derive_key(base_key: u32) -> ([u8; 8], [u8; 8]) {
    let k = base_key.to_le_bytes().to_vec();

    let key1: [u8; 7] = [k[0], k[1], k[2], k[3], k[0], k[1], k[2]];
    let key2: [u8; 7] = [k[3], k[0], k[1], k[2], k[3], k[0], k[1]];

    return (transform_key(key1), transform_key(key2));
}

fn remove_des(data: Vec<u8>, rid: u32) -> Vec<u8> {
    let (k1, k2) = derive_key(rid);

    let mut p1 = des_ecb(&k1, &mut data[..8].to_vec(), Des::Decrypt);
    let mut p2 = des_ecb(&k2, &mut data[8..].to_vec(), Des::Decrypt);
    p1.append(&mut p2);

    p1
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

pub fn get_account_info(parser: &mut Parser, rid: String) -> Option<String> {
    let mut results: Vec<String> = Vec::new();

    let key_path = format!("SAM\\Domains\\Account\\Users\\{}", rid);
    let akey = parser.get_key(&key_path, false).unwrap().unwrap();
    let rid_num = u32::from_be_bytes(hex::decode(rid).unwrap().try_into().unwrap());

    match akey.get_value("V").unwrap().get_content().0 {
        CellValue::Binary(v) => {
            let vdata: VDATA = unsafe { std::ptr::read(v.as_ptr() as *const _) };
            let idata = v[204..].to_vec();

            // Get NTLM hash
            let mut start_offset = vdata.ntlm_hash.offset as usize;
            let mut end_offset = start_offset + vdata.ntlm_hash.length as usize;
            let ntlm_hash = hex::encode(remove_des(idata[start_offset..end_offset].to_vec(), rid_num));

            // Get username
            start_offset = vdata.username.offset as usize;
            end_offset = start_offset + vdata.username.length as usize;
            let username = String::from_utf8(idata[start_offset..end_offset].to_vec()).unwrap();

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

            results.push(format!("{}\t{}\t{}\t{}\t{}\t{}", rid_num, username, fullname, comment, user_comment, ntlm_hash));
        },
        _ => {
            println!("[-] Failed to read value F under Domains\\Account key");
        }
    }

    if results.len() != 0 {
        Some(results.join("\n"))
    } else {
        None
    }
}