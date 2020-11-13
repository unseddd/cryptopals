use alloc::vec::Vec;

use craes::ecb;

#[derive(Debug)]
pub enum Error {
    InvalidEmailKey,
    InvalidUidKey,
    InvalidRoleKey,
    InvalidEmailValue,
    InvalidUidValue,
    InvalidRoleValue,
    KeyNotFound,
}

const AMP_KEY: u8 = 0x26;  // '&'
const EQ_KEY: u8 = 0x3d;  // '='

fn find_key(buf: &[u8], key: u8) -> Result<usize, Error> {
    for (i, b) in buf.iter().enumerate() {
        if *b == key {
            return Ok(i);
        }
    }

    Err(Error::KeyNotFound)
}

#[derive(Debug, PartialEq)]
pub struct Profile {
    pub email: Vec<u8>,
    pub uid: u64,
    pub role: Vec<u8>,
}

impl Profile {
    /// Create a default Profile
    pub fn new() -> Self {
        Self {
            email: Vec::new(),
            uid: 0,
            role: b"user".to_vec(),
        }
    }

    /// Create a Profile for the given email
    pub fn from_email(email: &str) -> Result<Self, Error> {
        let email = email.as_bytes();
        if email.contains(&AMP_KEY) || email.contains(&EQ_KEY) {
            return Err(Error::InvalidEmailValue);
        }

        Ok(Profile{ email: email.to_vec(), uid: 10, role: b"user".to_vec()})
    }

    /// Deserialize a profile string
    ///
    /// Example:
    ///
    /// let profile_str = "email=alice@bob.com&uid=42&role=user";
    /// let profile = Profile::from_str(&profile_str).unwrap();
    /// let exp_profile = Profile {
    ///     email: b"alice@bob.com".to_vec(),
    ///     uid: 42,
    ///     role: b"user".to_vec(),
    /// };
    /// assert_eq!(profile, exp_profile);
    pub fn from_str(encoded: &str) -> Result<Profile, Error> {
        let encoded = encoded.as_bytes();

        Self::from_bytes(encoded)
    }

    /// Deserialize a profile string
    ///
    /// Example:
    ///
    /// let profile_str = b"email=alice@bob.com&uid=42&role=user";
    /// let profile = Profile::from_bytes(&profile_str).unwrap();
    /// let exp_profile = Profile {
    ///     email: b"alice@bob.com".to_vec(),
    ///     uid: 42,
    ///     role: b"user".to_vec(),
    /// };
    /// assert_eq!(profile, exp_profile);
    pub fn from_bytes(encoded: &[u8]) -> Result<Profile, Error> {
        let mut amp_idx = find_key(encoded, AMP_KEY)?;
        let (email_str, encoded) = encoded.split_at(amp_idx);
        let email = Self::deserialize_email(email_str)?;

        amp_idx = find_key(&encoded[1..], AMP_KEY)?;
        let (uid_str, encoded) = encoded[1..].split_at(amp_idx);
        let uid = Self::deserialize_uid(uid_str)?;

        let role = Self::deserialize_role(&encoded[1..])?;

        Ok(Profile{ email: email, uid: uid, role: role })
    }

    fn deserialize_email(email_str: &[u8]) -> Result<Vec<u8>, Error> {
        let mut email_iter = email_str.split(|b| *b == EQ_KEY);

        if let Some(email_key) = email_iter.next() {
            if email_key[..] != b"email"[..] {
                return Err(Error::InvalidEmailKey);
            }
        }

        let res = if let Some(email) = email_iter.next() {
            if email.contains(&AMP_KEY) || email.contains(&EQ_KEY) {
                Err(Error::InvalidEmailValue)
            } else {
                Ok(email.to_vec())
            }
        } else {
            Err(Error::InvalidEmailValue)
        };

        // multiple '=' in the email value
        if email_iter.next().is_some() {
            return Err(Error::InvalidEmailValue);
        }

        res
    }

    fn deserialize_uid(uid_str: &[u8]) -> Result<u64, Error> {
        let mut uid_iter = uid_str.split(|b| *b == EQ_KEY);

        if let Some(uid_key) = uid_iter.next() {
            if uid_key[..] != b"uid"[..] {
                return Err(Error::InvalidUidKey);
            }
        } else {
            return Err(Error::InvalidUidKey);
        }

        if let Some(uid_val) = uid_iter.next() {
            if uid_val.contains(&AMP_KEY) || uid_val.contains(&EQ_KEY) {
                return Err(Error::InvalidUidValue);
            }

            let uid = core::str::from_utf8(uid_val)
                .map_err(|_| Error::InvalidUidValue)?
                .parse::<u64>()
                .map_err(|_| Error::InvalidUidValue)?;

            Ok(uid)
        } else {
            Err(Error::InvalidUidValue)
        }
    }

    fn deserialize_role(role_str: &[u8]) -> Result<Vec<u8>, Error> {
        let mut role_iter = role_str.split(|b| *b == EQ_KEY);

        if let Some(role_key) = role_iter.next() {
            if role_key[..] != b"role"[..] {
                return Err(Error::InvalidRoleKey);
            }
        } else {
            return Err(Error::InvalidRoleKey);
        }

        if let Some(role) = role_iter.next() {
            if role[..] != b"user"[..] && role[..] != b"admin"[..] {
                return Err(Error::InvalidRoleValue);
            }

            Ok(role.to_vec())
        } else {
            Err(Error::InvalidRoleValue)
        }
    }
}

impl core::fmt::Display for Profile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f,
               "email={}&uid={}&role={}",
               core::str::from_utf8(self.email.as_ref()).unwrap(),
               self.uid,
               core::str::from_utf8(self.role.as_ref()).unwrap()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_profile() {
        let profile = Profile::from_str("email=valid@email.org&uid=420&role=user").unwrap();
        let exp_profile = Profile{ email: b"valid@email.org".to_vec(), uid: 420, role: b"user".to_vec() };

        assert_eq!(profile, exp_profile);
    }

    #[test]
    fn check_bad_profile() {
        // invalid role, trailing '&'
        assert!(Profile::from_str("email=valid@email.org&uid=420&role=user&").is_err());
        // invalid role, not 'user' or 'admin'
        assert!(Profile::from_str("email=valid@email.org&uid=420&role=simp").is_err());
        // invalid UID
        assert!(Profile::from_str("email=valid@email.org&uid=doggo&role=user").is_err());
        // invalid email
        assert!(Profile::from_str("email=invalid@email=org&uid=420&role=user").is_err());
        // missing email
        assert!(Profile::from_str("uid=doggo&role=user").is_err());
        // missing uid
        assert!(Profile::from_str("email=valid@email.org&role=user").is_err());
        // missing role
        assert!(Profile::from_str("email=valid@email.org&uid=420&").is_err());
    }
}
