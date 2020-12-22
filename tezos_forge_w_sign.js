"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __read = (this && this.__read) || function (o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
};
var __spread = (this && this.__spread) || function () {
    for (var ar = [], i = 0; i < arguments.length; i++) ar = ar.concat(__read(arguments[i]));
    return ar;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var node_fetch_1 = __importDefault(require("node-fetch"));
var log = __importStar(require("loglevel"));
var logger = log.getLogger('conseiljs');
var bs58check_1 = __importDefault(require("bs58check"));
var big_integer_1 = __importDefault(require("big-integer"));
var GeneratePassword = __importStar(require("generate-password"));
var blakejs_1 = __importDefault(require("blakejs"));
var conseiljs_1 = require("conseiljs");
conseiljs_1.registerFetch(node_fetch_1.default);
conseiljs_1.registerLogger(logger);
var tezosNode = 'https://delphinet-tezos.giganode.io';
var TezosConstants;
(function (TezosConstants) {
    TezosConstants.OperationGroupWatermark = '03';
    TezosConstants.DefaultTransactionStorageLimit = 496; // 300, carthage?!
    TezosConstants.DefaultTransactionGasLimit = 10600;
    TezosConstants.DefaultDelegationStorageLimit = 0;
    TezosConstants.DefaultDelegationGasLimit = 10000;
    TezosConstants.DefaultAccountOriginationStorageLimit = 496; // 277
    TezosConstants.DefaultAccountOriginationGasLimit = 10600;
    TezosConstants.DefaultAccountOriginationFee = 1266;
    TezosConstants.DefaultKeyRevealFee = 1270;
    TezosConstants.DefaultDelegationFee = 1258;
    TezosConstants.P005ManagerContractWithdrawalGasLimit = 26283;
    TezosConstants.P005ManagerContractDepositGasLimit = 15285;
    TezosConstants.P005ManagerContractWithdrawalStorageLimit = 496; // 300
    /**
     * Outbound operation queue timeout in seconds. After this period, TezosOperationQueue will attempt to submit the transactions currently in queue.
     */
    TezosConstants.DefaultBatchDelay = 25;
    /**
     * Mainnet block time in seconds.
     */
    TezosConstants.DefaultBlockTime = 60;
})(TezosConstants || (TezosConstants = {}));
var KeyStoreType;
(function (KeyStoreType) {
    KeyStoreType[KeyStoreType["Mnemonic"] = 0] = "Mnemonic";
    KeyStoreType[KeyStoreType["Fundraiser"] = 1] = "Fundraiser";
    KeyStoreType[KeyStoreType["Hardware"] = 2] = "Hardware";
})(KeyStoreType || (KeyStoreType = {}));
var KeyStoreCurve;
(function (KeyStoreCurve) {
    KeyStoreCurve[KeyStoreCurve["ED25519"] = 0] = "ED25519";
    KeyStoreCurve[KeyStoreCurve["SECP256K1"] = 1] = "SECP256K1";
    KeyStoreCurve[KeyStoreCurve["SECP256R1"] = 2] = "SECP256R1";
})(KeyStoreCurve || (KeyStoreCurve = {}));
var wrapper = require('./Wrapper'); // wrappers for libsodium
var operationTypes = new Map([
    [0, 'endorsement'],
    [1, 'seedNonceRevelation'],
    [2, 'doubleEndorsementEvidence'],
    [3, 'doubleBakingEvidence'],
    [4, 'accountActivation'],
    [5, 'proposal'],
    [6, 'ballot'],
    [7, 'reveal'],
    [8, 'transaction'],
    [9, 'origination'],
    [10, 'delegation'],
    [107, 'reveal'],
    [108, 'transaction'],
    [109, 'origination'],
    [110, 'delegation'] // >=P005
]);
var sepyTnoitarepo = __spread(operationTypes.keys()).reduce(function (m, k) {
    var _a;
    var v = operationTypes.get(k) || '';
    if (m[v] > k) {
        return m;
    }
    return __assign(__assign({}, m), (_a = {}, _a[v] = k, _a));
}, new Map());
var operation = {
    "branch": "BL93KWYucYzFhiEgLUtfTuGZ3BzSUz6Lsz5PYjLcqPHAJeCA3u3",
    "contents": [
    // {  
    //     "kind":"reveal",
    //     "source":"tz1c3UBQtTPH4tpTjzAJpQcNbjCaHKpnJHmy",
    //     "fee":"1420",
    //     "counter":"962412",
    //     "gas_limit":"10000",
    //     "storage_limit":"0",
    //     "public_key":"edpkv6ytqQAFWYmjvp5CeH9ns7eYXt8PZByftdvkTgMV1bkxHz2YDt"
    // },
    // {
    //     "kind": "transaction",
    //     "source": "tz1g1Li3iY9gC3ghKXdstXV8xwhMwBaUb8cG",
    //     "fee": "1350",
    //     "counter": "889343",
    //     "gas_limit": `${TezosConstants.DefaultTransactionGasLimit}`,
    //     "storage_limit": `${TezosConstants.DefaultAccountOriginationStorageLimit}`,
    //     "amount": "150",
    //     "destination": "tz1c3UBQtTPH4tpTjzAJpQcNbjCaHKpnJHmy"
    // },
    // {
    //     "kind": "delegation",
    //     "source": "tz1c3UBQtTPH4tpTjzAJpQcNbjCaHKpnJHmy",
    //     "fee": "396",
    //     "counter": "962414",
    //     "gas_limit": "1100",
    //     "storage_limit": "257",
    //     "delegate": "tz1aWXP237BLwNHJcCD4b3DutCevhqq2T1Z9"
    // },
    // {
    //     "kind": "delegation",   // cancel delegate relationship with the baker you delegate now.
    //     "source": "tz1c3UBQtTPH4tpTjzAJpQcNbjCaHKpnJHmy",
    //     "fee": "396",
    //     "counter": "962415",
    //     "gas_limit": "1100",
    //     "storage_limit": "257",
    // }
    ]
};
var keystore = {
    publicKey: 'edpkvWLphnAcReCXuB23D3dbnZbzqKiob45JTNCsgYbDkwLHUuuGs3',
    secretKey: 'edskRjhatFNf9w9h6mS6jkrqBptn8RnPriWmhqDW21ArHVVPgPF36cLmg33cxLUAiPQLZiFBvBa7gifWNhZ6QvWfsTdQZeMyyM',
    publicKeyHash: 'tz1g1Li3iY9gC3ghKXdstXV8xwhMwBaUb8cG',
    seed: '',
    curve: 0,
    storeType: KeyStoreType.Fundraiser
};
function generateSaltForPwHash() {
    return __awaiter(this, void 0, void 0, function () {
        var s;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, wrapper.salt()];
                case 1:
                    s = _a.sent();
                    return [2 /*return*/, s];
            }
        });
    });
}
function encryptMessage(message, passphrase, salt) {
    return __awaiter(this, void 0, void 0, function () {
        var keyBytes, n, nonce, s, cipherText;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, wrapper.pwhash(passphrase, salt)];
                case 1:
                    keyBytes = _a.sent();
                    return [4 /*yield*/, wrapper.nonce()];
                case 2:
                    n = _a.sent();
                    nonce = Buffer.from(n);
                    return [4 /*yield*/, wrapper.pclose(message, nonce, keyBytes)];
                case 3:
                    s = _a.sent();
                    cipherText = Buffer.from(s);
                    return [2 /*return*/, Buffer.concat([nonce, cipherText])];
            }
        });
    });
}
function decryptMessage(message, passphrase, salt) {
    return __awaiter(this, void 0, void 0, function () {
        var keyBytes, m;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, wrapper.pwhash(passphrase, salt)];
                case 1:
                    keyBytes = _a.sent();
                    return [4 /*yield*/, wrapper.popen(message, keyBytes)];
                case 2:
                    m = _a.sent();
                    return [2 /*return*/, Buffer.from(m)];
            }
        });
    });
}
function forgeOperations(branch, operations) {
    var encoded = writeBranch(branch);
    operations.forEach(function (m) { return encoded += encodeOperation(m); });
    return encoded;
}
function writeInt(value) {
    if (value < 0) {
        throw new Error('Use writeSignedInt to encode negative numbers');
    }
    //@ts-ignore
    return Buffer.from(Buffer.from(twoByteHex(value), 'hex').map(function (v, i) { return i === 0 ? v : v ^ 0x80; }).reverse()).toString('hex');
}
function encodeOperation(message) {
    if (message.kind === 'transaction') {
        return encodeTransaction(message);
    }
    if (message.kind === 'reveal') {
        return encodeReveal(message);
    }
    if (message.kind === 'delegation') {
        return encodeDelegation(message);
    }
    return "unknow operation!!";
}
function encodeReveal(reveal) {
    var hex = writeInt(sepyTnoitarepo['reveal']);
    hex += writeAddress(reveal.source).slice(2);
    hex += writeInt(parseInt(reveal.fee));
    hex += writeInt(parseInt(reveal.counter));
    hex += writeInt(parseInt(reveal.gas_limit));
    hex += writeInt(parseInt(reveal.storage_limit));
    hex += writePublicKey(reveal.public_key);
    return hex;
}
function encodeDelegation(delegation) {
    if (delegation.kind !== 'delegation') {
        throw new Error('Incorrect operation type');
    }
    var hex = writeInt(sepyTnoitarepo['delegation']);
    hex += writeAddress(delegation.source).slice(2);
    hex += writeInt(parseInt(delegation.fee));
    hex += writeInt(parseInt(delegation.counter));
    hex += writeInt(parseInt(delegation.gas_limit));
    hex += writeInt(parseInt(delegation.storage_limit));
    if (delegation.delegate !== undefined && delegation.delegate !== '') {
        hex += writeBoolean(true);
        hex += writeAddress(delegation.delegate).slice(2);
    }
    else {
        hex += writeBoolean(false);
    }
    return hex;
}
function encodeTransaction(transaction) {
    var hex = writeInt(sepyTnoitarepo['transaction']);
    hex += writeAddress(transaction.source).slice(2);
    hex += writeInt(parseInt(transaction.fee));
    hex += writeInt(parseInt(transaction.counter));
    hex += writeInt(parseInt(transaction.gas_limit));
    hex += writeInt(parseInt(transaction.storage_limit));
    hex += writeInt(parseInt(transaction.amount));
    hex += writeAddress(transaction.destination);
    hex += '00';
    return hex;
}
function writePublicKey(publicKey) {
    console.log("== writePublicKey ==");
    if (publicKey.startsWith("edpk")) { // ed25519
        return "00" + bs58check_1.default.decode(publicKey).slice(4).toString("hex");
    }
    else if (publicKey.startsWith("sppk")) { // secp256k1
        return "01" + bs58check_1.default.decode(publicKey).slice(4).toString("hex");
    }
    else if (publicKey.startsWith("p2pk")) { // secp256r1 (p256)
        return "02" + bs58check_1.default.decode(publicKey).slice(4).toString("hex");
    }
    else {
        throw new Error('Unrecognized key type');
    }
}
function writeBoolean(value) {
    return value ? "ff" : "00";
}
function writeAddress(address) {
    console.log("writeAddress =>");
    var hex = bs58check_1.default.decode(address).slice(3).toString("hex");
    // console.log((base58check.decode(address) as Buffer).toString("hex"));
    console.log(hex);
    if (address.startsWith("tz1")) {
        return "0000" + hex;
    }
    else if (address.startsWith("tz2")) {
        return "0001" + hex;
    }
    else if (address.startsWith("tz3")) {
        return "0002" + hex;
    }
    else if (address.startsWith("KT1")) {
        return "01" + hex + "00";
    }
    else {
        throw new Error("Unrecognized address prefix: " + address.substring(0, 3));
    }
}
function writeBranch(branch) {
    return bs58check_1.default.decode(branch).slice(2).toString("hex");
}
function twoByteHex(n) {
    if (n < 128) {
        return ('0' + n.toString(16)).slice(-2);
    }
    var h = '';
    if (n > 2147483648) {
        var r = big_integer_1.default(n);
        while (r.greater(0)) {
            h = ('0' + (r.and(127)).toString(16)).slice(-2) + h;
            r = r.shiftRight(7);
        }
    }
    else {
        var r = n;
        while (r > 0) {
            h = ('0' + (r & 127).toString(16)).slice(-2) + h;
            r = r >> 7;
        }
    }
    return h;
}
function getAccountInfo() {
    return __awaiter(this, void 0, void 0, function () {
        var counter, hash;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0: return [4 /*yield*/, conseiljs_1.TezosNodeReader.getCounterForAccount(tezosNode, keystore.publicKeyHash)];
                case 1:
                    counter = _a.sent();
                    console.log("counter: ", counter + 1);
                    return [4 /*yield*/, conseiljs_1.TezosNodeReader.getBlockAtOffset(tezosNode, 0)];
                case 2:
                    hash = (_a.sent()).hash;
                    console.log("\nblockHead: " + hash);
                    return [2 /*return*/, { counter: (counter + 1).toString(), blockHead: hash }];
            }
        });
    });
}
function prepareSigner() {
    return __awaiter(this, void 0, void 0, function () {
        var secretKey, passphrase, salt;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    secretKey = bs58check_1.default.decode(keystore.secretKey).slice(4);
                    console.log("\nsecretKey: " + secretKey.toString("hex"));
                    passphrase = GeneratePassword.generate({ length: 32, numbers: true, symbols: true, lowercase: true, uppercase: true });
                    return [4 /*yield*/, generateSaltForPwHash()];
                case 1:
                    salt = _a.sent();
                    return [4 /*yield*/, encryptMessage(secretKey, passphrase, salt)];
                case 2:
                    secretKey = _a.sent();
                    return [2 /*return*/, { secretKey: secretKey, passphrase: passphrase, salt: salt }];
            }
        });
    });
}
function forge(operation) {
    return __awaiter(this, void 0, void 0, function () {
        var forgedOperationGroup, rawBytes;
        return __generator(this, function (_a) {
            forgedOperationGroup = forgeOperations(operation.branch, operation.contents);
            rawBytes = Buffer.from(TezosConstants.OperationGroupWatermark + forgedOperationGroup, 'hex');
            console.log("\nforged bytes: " + rawBytes.toString("hex"));
            return [2 /*return*/, { rawBytes: rawBytes, forgedOperationGroup: forgedOperationGroup }];
        });
    });
}
function sign(rawBytes, secretKey, passphrase, salt, forgedOperationGroup) {
    return __awaiter(this, void 0, void 0, function () {
        var bhash, d, opSignature, signedOpGroup;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    bhash = Buffer.from(blakejs_1.default.blake2b(rawBytes, null, 32));
                    console.log("\nblake hash: " + bhash.toString("hex"));
                    return [4 /*yield*/, decryptMessage(secretKey, passphrase, salt)];
                case 1:
                    d = _a.sent();
                    return [4 /*yield*/, wrapper.sign(bhash, d)];
                case 2:
                    opSignature = _a.sent();
                    console.log("\nsignature: " + Buffer.from(opSignature).toString("hex"));
                    signedOpGroup = Buffer.concat([Buffer.from(forgedOperationGroup, 'hex'), Buffer.from(opSignature)]);
                    console.log("\nsigned bytes: " + signedOpGroup.toString("hex"));
                    return [2 /*return*/, signedOpGroup.toString("hex")];
            }
        });
    });
}
function injectOperation(signedBytes) {
    return __awaiter(this, void 0, void 0, function () {
        var url, payloadStr, result, text;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    url = tezosNode + "/injection/operation?chain=main";
                    payloadStr = JSON.stringify(signedBytes);
                    return [4 /*yield*/, node_fetch_1.default(url, { method: 'post', body: payloadStr, headers: { 'content-type': 'application/json' } })];
                case 1:
                    result = _a.sent();
                    return [4 /*yield*/, result.text()];
                case 2:
                    text = _a.sent();
                    console.log("\nwaiting for txId " + text + " about 1 min");
                    return [2 /*return*/];
            }
        });
    });
}
function generateTransaction(obj) {
    var to = obj.to, from = obj.from;
    return {
        "kind": "transaction",
        "source": from,
        "fee": "1350",
        "counter": "",
        "gas_limit": "" + TezosConstants.DefaultTransactionGasLimit,
        "storage_limit": "" + TezosConstants.DefaultAccountOriginationStorageLimit,
        "amount": "150",
        "destination": to
    };
}
function generateDelegate(obj) {
    // TODO 
}
function generateReveal(obj) {
    // TODO
}
(function () {
    return __awaiter(this, void 0, void 0, function () {
        var operationShell, op, _a, counter, blockHead, _b, secretKey, passphrase, salt_1, _c, rawBytes, forgedOperationGroup, signedBytes, e_1;
        return __generator(this, function (_d) {
            switch (_d.label) {
                case 0:
                    _d.trys.push([0, 6, , 7]);
                    operationShell = {
                        branch: "",
                        contents: []
                    };
                    op = generateTransaction({
                        to: "tz1c3UBQtTPH4tpTjzAJpQcNbjCaHKpnJHmy",
                        from: "tz1g1Li3iY9gC3ghKXdstXV8xwhMwBaUb8cG"
                    });
                    operationShell.contents.push(op);
                    return [4 /*yield*/, getAccountInfo()];
                case 1:
                    _a = _d.sent(), counter = _a.counter, blockHead = _a.blockHead;
                    op["counter"] = counter;
                    operationShell["branch"] = blockHead;
                    return [4 /*yield*/, prepareSigner()];
                case 2:
                    _b = _d.sent(), secretKey = _b.secretKey, passphrase = _b.passphrase, salt_1 = _b.salt;
                    console.log("\n");
                    console.log(operationShell);
                    console.log("\n");
                    return [4 /*yield*/, forge(operationShell)];
                case 3:
                    _c = _d.sent(), rawBytes = _c.rawBytes, forgedOperationGroup = _c.forgedOperationGroup;
                    return [4 /*yield*/, sign(rawBytes, secretKey, passphrase, salt_1, forgedOperationGroup)]; // ==== step 3 signing ==== //
                case 4:
                    signedBytes = _d.sent() // ==== step 3 signing ==== //
                    ;
                    return [4 /*yield*/, injectOperation(signedBytes)];
                case 5:
                    _d.sent(); // ==== step 4 inject signed bytes ==== //   
                    return [3 /*break*/, 7];
                case 6:
                    e_1 = _d.sent();
                    throw e_1;
                case 7: return [2 /*return*/];
            }
        });
    });
})();
