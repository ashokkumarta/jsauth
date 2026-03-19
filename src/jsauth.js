export function validate (accessToken) {
    // Parse token and get user object
const ISSUER_KEY =  'iss';
const ISSUER_VALUE =  'https://lab.shinova.in/';
const ISSUED_AT_KEY = "iat";
const EXPIRES_AT_KEY = "exp";
const AUD_KEY = "aud";
const EMAIL_KEY = "email";
const NAME_KEY = "name";
const ALLOWED_ACTIONS_KEY = "allowed-actions";
const ALLOWED_DATA_KEY = "allowed-data";
const JTI_KEY = "jti";

const AUTHZ_MODEL = 'IMPLIED';

const CRYPT_ALGORITHM_VALUE = "bit_map"
const CRYPT_KEY = "crypt"

var unverified = {};
var ct = Date.now()/1000;

try {
    unverified = JSON.parse(atob(accessToken.split('.')[1]));
} catch (err) {
    throw new Error("Invalid access token [Error parsing token string]");
}


if (unverified[ISSUER_KEY] !== ISSUER_VALUE) {
    throw new Error("Invalid access token [Token not from trusted source]");
} else if (unverified[ISSUED_AT_KEY] > ct) {
    throw new Error("Invalid access token [Token is not yet valid]");
} else if (unverified[EXPIRES_AT_KEY] < ct) {
    throw new Error("Invalid access token [Token expired]");
}

var aud = unverified[AUD_KEY];
if (!aud) {
    throw new Error("Invalid access token [aud claim invalid]");
}

var user = {
    _id: aud,
    _email: unverified[EMAIL_KEY],
    _name: unverified[NAME_KEY],
    _allowed_actions: unverified[ALLOWED_ACTIONS_KEY],
    _allowed_data: unverified[ALLOWED_DATA_KEY],
    _iat: unverified[ISSUED_AT_KEY],
    _exp: unverified[EXPIRES_AT_KEY],
    _jti: unverified[JTI_KEY],
    _crypt: unverified[CRYPT_KEY],

    process: function(){
        console.log("Processing permissoins bitmap");
        if (this._crypt) {
            var cvals = this._crypt.split(":");
            if (cvals[0] == CRYPT_ALGORITHM_VALUE) {
                if (supported(cvals[1], cvals[2])) {
                    this._allowed_actions = decrypt(cvals[2], this._allowed_actions);
                }
            } 
        }
    },

    id: function(){
      return this._id;
    },
    email: function(){
        return this._email;
      },
    name: function(){
      return this._name;
    },
    allowedActions: function(){
        return this._allowed_actions;
    },
    allowedData: function(){
        return this._allowed_data;
    },
    allowedPages: function(){
        const entities = this._allowed_actions.map(function (perm_code) {
            return perm_code.substring(0, perm_code.lastIndexOf("-"));
        });
        const pages = entities.filter(entity =>
            entity.includes("-P-")
        );
        const upages = [...new Set(pages)];
        return upages;
    },
    allowedApis: function(){
        const entities = this._allowed_actions.map(function (perm_code) {
            return perm_code.substring(0, perm_code.lastIndexOf("-"));
        });
        const apis = entities.filter(entity =>
            entity.includes("-API-")
        );
        const uapis = [...new Set(apis)];
        return uapis;
    },
    allowedModules: function(){
        console.log("Processing allowedModules with: ", this._allowed_actions);
        const modules = this._allowed_actions.map(function (perm_code) {
            return perm_code.substring(0, perm_code.indexOf("-"));
        });
        const umodules = [...new Set(modules)];
        return umodules;
    },
    issuedAt: function(){
        return this._iat;
    },
    expiresAt: function(){
        return this._exp;
    },
    tokenId: function(){
        return this._jti;
    },
    checkAccess: function(data_code, perm_code){
        return this.checkDataAccess(data_code) && this.checkRoleAccess(perm_code);
    },
    checkAccess: function(data_code, page_code, action_code){
        return this.checkDataAccess(data_code) && this.checkRoleAccess(page_code, action_code);
    },
    checkRoleAccess: function(page_code, action_code){
        perm_code = page_code + '-' + action_code;
        return checkRoleAccess(perm_code);
    },
    checkRoleAccess: function(perm_code){
        if (this._allowed_actions.includes(perm_code)) {
            return true;
        }
        if (AUTHZ_MODEL === 'IMPLIED') {
            for (var i = 0; i < this._allowed_actions.length; i++) {
                if (this._allowed_actions[i].startsWith(perm_code)) {
                    return true;
                }
            }
        } 
        return false;
    },
    checkDataAccess: function(data_code){
        if (!this._allowed_data.includes(data_code)) {
            return false;
        }
        return true;
    },

}
// Process user permissions
user.process();

return user;
}

const PERMS_BASE_URL = "https://raw.githubusercontent.com/SMRFT/Login_security_backend/refs/heads/release/auth/permissions_master"
const PERMS_EXT = ".lst"

var master_permissions = new Map();
var master_versions = new Set();

function supported(permsVer, permsHash) {
    if (master_permissions.has(permsHash)) {
        return true;
    }
    if (master_versions.has(permsVer)) {
        return false;
    } 
    load_permissions(permsVer, permsHash)
    return master_permissions.has(permsHash);
}

const load_permissions = (permVer, permsHash) => {
    var fullUrl = PERMS_BASE_URL + (permVer ? `_${permVer}` : '') + PERMS_EXT
    master_versions.add(permVer)

    // Synchronous request to fetch permissions list
    var xhr = new XMLHttpRequest();
    xhr.open("GET", fullUrl, false);
    xhr.send();
    if (xhr.status === 200) {
        var perms = xhr.responseText.split('\n').map(line => line.trim()).filter(line => line.length > 0);
        master_permissions.set(permsHash, perms);
    } else {
        console.error(`Failed to load permissions from ${fullUrl}: ${xhr.statusText}`);
    }
}

function decrypt(permsHash, base64BitMap) {
    console.log("Decrypting permissions");
    const decoded_bytes = base64ToBytes(base64BitMap);
    const perms = master_permissions.get(permsHash);
    var allowed_actions = [];
    for (var i = 0; i < perms.length; i++) {
        var byteIndex = Math.floor(i / 8);
        var bitIndex = (i) % 8;
        bitIndex = 7 - bitIndex; // Reverse bit order for correct mapping
        if (byteIndex < decoded_bytes.length) {
            var byte = decoded_bytes[byteIndex];
            if ((byte & (1 << bitIndex)) !== 0) {
                allowed_actions.push(perms[i]);
            }
        }
    }
    console.log("Returning allowed_actions from decrypt: ",allowed_actions);
    return allowed_actions;
}

const base64ToBytes = (b64) => {
    // Decode the Base64 string to a raw binary string
    const binaryString = atob(b64); 
    // Create a Uint8Array from the binary string's character codes
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
};

