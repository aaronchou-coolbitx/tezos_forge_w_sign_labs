import fetch from 'node-fetch';
import * as log from 'loglevel';
const logger = log.getLogger('conseiljs');
import base58check from "bs58check";
import bigInt from 'big-integer';
import * as GeneratePassword from 'generate-password'
import blakejs from 'blakejs';
import { TezosNodeReader, registerFetch, registerLogger } from "conseiljs";
registerFetch(fetch);
registerLogger(logger);

const tezosNode = 'https://delphinet-tezos.giganode.io';

namespace TezosConstants {
    export const OperationGroupWatermark = '03';
    export const DefaultTransactionStorageLimit = 496; // 300, carthage?!
    export const DefaultTransactionGasLimit = 10600;
    export const DefaultDelegationStorageLimit = 0;
    export const DefaultDelegationGasLimit = 10000;
    export const DefaultAccountOriginationStorageLimit = 496; // 277
    export const DefaultAccountOriginationGasLimit = 10600;
    export const DefaultAccountOriginationFee = 1266;
    export const DefaultKeyRevealFee = 1270;
    export const DefaultDelegationFee = 1258;
    export const P005ManagerContractWithdrawalGasLimit = 26283;
    export const P005ManagerContractDepositGasLimit = 15285;
    export const P005ManagerContractWithdrawalStorageLimit = 496; // 300

    /**
     * Outbound operation queue timeout in seconds. After this period, TezosOperationQueue will attempt to submit the transactions currently in queue.
     */
    export const DefaultBatchDelay = 25;

    /**
     * Mainnet block time in seconds.
     */
    export const DefaultBlockTime = 60;
}

interface KeyStore {
    publicKey: string;
    secretKey: string;
    publicKeyHash: string;
    curve: KeyStoreCurve;
    storeType: KeyStoreType;
    seed?: string;
    derivationPath?: string;
}

interface OperationShell {
    branch: string,
    contents: Transaction[]
}

interface Transaction {
    kind: string;
    source: string;
    fee: string;
    counter: string;
    gas_limit: string,
    storage_limit: string;
    amount: string;
    destination: string;
}

enum KeyStoreType {
    Mnemonic,
    Fundraiser,
    Hardware
}

enum KeyStoreCurve {
    ED25519,
    SECP256K1,
    SECP256R1
}

const wrapper = require('./Wrapper');  // wrappers for libsodium

const operationTypes: Map<number, string> = new Map([
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
    [107, 'reveal'], // >=P005
    [108, 'transaction'], // >=P005
    [109, 'origination'], // >=P005
    [110, 'delegation'] // >=P005
]);

const sepyTnoitarepo: Map<string, number> = [...operationTypes.keys()].reduce((m, k) => { const v = operationTypes.get(k) || ''; if (m[v] > k) { return m; }  return { ...m, [v]: k } }, new Map());

let operation = {
    "branch": "BL93KWYucYzFhiEgLUtfTuGZ3BzSUz6Lsz5PYjLcqPHAJeCA3u3",
    "contents":
        [
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

const keystore:KeyStore = {
    publicKey: 'edpkvWLphnAcReCXuB23D3dbnZbzqKiob45JTNCsgYbDkwLHUuuGs3',
    secretKey: 'edskRjhatFNf9w9h6mS6jkrqBptn8RnPriWmhqDW21ArHVVPgPF36cLmg33cxLUAiPQLZiFBvBa7gifWNhZ6QvWfsTdQZeMyyM',
    publicKeyHash: 'tz1g1Li3iY9gC3ghKXdstXV8xwhMwBaUb8cG',
    seed: '',
    curve: 0,
    storeType: KeyStoreType.Fundraiser
};

async function generateSaltForPwHash() : Promise<Buffer> {
    const s = await wrapper.salt();
    return s;
}

async function encryptMessage(message: Buffer, passphrase: string, salt: Buffer) : Promise<Buffer> {
    const keyBytes = await wrapper.pwhash(passphrase, salt)
    const n = await wrapper.nonce();
    const nonce = Buffer.from(n);
    const s = await wrapper.pclose(message, nonce, keyBytes);
    const cipherText = Buffer.from(s);

    return Buffer.concat([nonce, cipherText]);
}

async function decryptMessage(message: Buffer, passphrase: string, salt: Buffer) : Promise<Buffer> {
    const keyBytes = await wrapper.pwhash(passphrase, salt)
    const m = await wrapper.popen(message, keyBytes);
    return Buffer.from(m);
}

function forgeOperations(branch: string, operations: any[]): string {
    let encoded = writeBranch(branch);
    operations.forEach(m => encoded += encodeOperation(m));
    return encoded;
}

function writeInt(value: number): string {
    if (value < 0) { throw new Error('Use writeSignedInt to encode negative numbers'); }
    //@ts-ignore
    return Buffer.from(Buffer.from(twoByteHex(value), 'hex').map((v, i) => { return i === 0 ? v : v ^ 0x80; }).reverse()).toString('hex');
}

function encodeOperation(message: any): string {
    if (message.kind === 'transaction') { return encodeTransaction(message); }
    if (message.kind === 'reveal') { return encodeReveal(message); }
    if (message.kind === 'delegation') { return encodeDelegation(message); }
    return "unknow operation!!";
}

function encodeReveal(reveal: any) {
    let hex = writeInt(sepyTnoitarepo['reveal']);
        hex += writeAddress(reveal.source).slice(2);
        hex += writeInt(parseInt(reveal.fee));
        hex += writeInt(parseInt(reveal.counter));
        hex += writeInt(parseInt(reveal.gas_limit));
        hex += writeInt(parseInt(reveal.storage_limit));
        hex += writePublicKey(reveal.public_key);

        return hex;
}

function encodeDelegation(delegation: any): string {
    if (delegation.kind !== 'delegation') { throw new Error('Incorrect operation type'); }

    let hex = writeInt(sepyTnoitarepo['delegation']);
    hex += writeAddress(delegation.source).slice(2);
    hex += writeInt(parseInt(delegation.fee));
    hex += writeInt(parseInt(delegation.counter));
    hex += writeInt(parseInt(delegation.gas_limit));
    hex += writeInt(parseInt(delegation.storage_limit));

    if (delegation.delegate !== undefined && delegation.delegate !== '') {
        hex += writeBoolean(true);
        hex += writeAddress(delegation.delegate).slice(2);
    } else {
        hex += writeBoolean(false);
    }

    return hex;
}


function encodeTransaction(transaction: any) {
    let hex = writeInt(sepyTnoitarepo['transaction']);
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


function writePublicKey(publicKey: string): string {
    console.log("== writePublicKey ==");
    if (publicKey.startsWith("edpk")) { // ed25519
        return "00" + base58check.decode(publicKey).slice(4).toString("hex");
    } else if (publicKey.startsWith("sppk")) { // secp256k1
        return "01" + base58check.decode(publicKey).slice(4).toString("hex");
    } else if (publicKey.startsWith("p2pk")) { // secp256r1 (p256)
        return "02" + base58check.decode(publicKey).slice(4).toString("hex");
    } else {
        throw new Error('Unrecognized key type');
    }
}

function writeBoolean(value: boolean): string {
    return value ? "ff" : "00";
}

function writeAddress(address: string): string {
    console.log("writeAddress =>");
    const hex = base58check.decode(address).slice(3).toString("hex");
    // console.log((base58check.decode(address) as Buffer).toString("hex"));
    console.log(hex);
    if (address.startsWith("tz1")) {
        return "0000" + hex;
    } else if (address.startsWith("tz2")) {
        return "0001" + hex;
    } else if (address.startsWith("tz3")) {
        return "0002" + hex;
    } else if (address.startsWith("KT1")) {
        return "01" + hex + "00";
    } else {
        throw new Error(`Unrecognized address prefix: ${address.substring(0, 3)}`);
    }
}
 
function writeBranch(branch: string) {
    return base58check.decode(branch).slice(2).toString("hex");
}

function twoByteHex(n: number): string {
    if (n < 128) { return ('0' + n.toString(16)).slice(-2); }

    let h = '';
    if (n > 2147483648) {
        let r = bigInt(n);
        while (r.greater(0)) {
            h = ('0' + (r.and(127)).toString(16)).slice(-2) + h;
            r = r.shiftRight(7);
        }
    } else {
        let r = n;
        while (r > 0) {
            h = ('0' + (r & 127).toString(16)).slice(-2) + h;
            r = r >> 7;
        }
    }

    return h;
}

async function getAccountInfo() {
    const counter = await TezosNodeReader.getCounterForAccount(tezosNode, keystore.publicKeyHash);
    console.log("counter: ", counter+1);

    const { hash } = await TezosNodeReader.getBlockAtOffset(tezosNode, 0);
    console.log(`\nblockHead: ${hash}` );
    return { counter: (counter+1).toString(), blockHead: hash };
}

async function prepareSigner(): Promise<any> {
    let secretKey:Buffer = base58check.decode(keystore.secretKey).slice(4);
    console.log(`\nsecretKey: ${secretKey.toString("hex")}`);
    const passphrase = GeneratePassword.generate({ length: 32, numbers: true, symbols: true, lowercase: true, uppercase: true });
    const salt = await generateSaltForPwHash();
    secretKey = await encryptMessage(secretKey, passphrase, salt);
    return { secretKey, passphrase, salt };
}

async function forge(operation: OperationShell): Promise<any> {
    const forgedOperationGroup = forgeOperations(operation.branch, operation.contents);
    let rawBytes = Buffer.from(TezosConstants.OperationGroupWatermark + forgedOperationGroup, 'hex');
    console.log(`\nforged bytes: ${rawBytes.toString("hex")}`);
    return { rawBytes, forgedOperationGroup };
}

async function sign(rawBytes: Buffer, secretKey: Buffer, passphrase: string, salt: Buffer, forgedOperationGroup: string): Promise<string> {
    let bhash = Buffer.from(blakejs.blake2b(rawBytes, null, 32)); //hashing 
    console.log(`\nblake hash: ${bhash.toString("hex")}`);
    let d = await decryptMessage(secretKey, passphrase, salt);
    const opSignature = await wrapper.sign(bhash, d);
    console.log(`\nsignature: ${Buffer.from(opSignature).toString("hex")}`);
    const signedOpGroup = Buffer.concat([Buffer.from(forgedOperationGroup, 'hex'), Buffer.from(opSignature)]);
    console.log(`\nsigned bytes: ${signedOpGroup.toString("hex")}`);
    return signedOpGroup.toString("hex");
}

async function injectOperation(signedBytes: string) {
    const url = `${tezosNode}/injection/operation?chain=main`
    const payloadStr = JSON.stringify(signedBytes);

    let result = await fetch(url, { method: 'post', body: payloadStr, headers: { 'content-type': 'application/json' } });
    let text = await result.text();
    console.log(`\nwaiting for txId ${text} about 1 min`);
}

function generateTransaction(obj) {
    let { to , from } = obj;
    return {
        "kind": "transaction",
        "source": from,
        "fee": "1350",
        "counter": "",
        "gas_limit": `${TezosConstants.DefaultTransactionGasLimit}`,
        "storage_limit": `${TezosConstants.DefaultAccountOriginationStorageLimit}`,
        "amount": "150",
        "destination": to
    }
}

function generateDelegate(obj) {
    // TODO 
}

function generateReveal(obj) {
    // TODO
}

(async function () {
    try {
        let operationShell = {
            branch: "",
            contents: [] as Transaction[]
        } as OperationShell;
        
        let op = generateTransaction({
            to: "tz1c3UBQtTPH4tpTjzAJpQcNbjCaHKpnJHmy",
            from: "tz1g1Li3iY9gC3ghKXdstXV8xwhMwBaUb8cG"
        });
    
        operationShell.contents.push(op);
    
        let { counter, blockHead } = await getAccountInfo();  // ==== step 0 get account info ==== //
        op["counter"] = counter;
        operationShell["branch"] = blockHead;
    
        let { secretKey, passphrase, salt } = await prepareSigner(); // ==== step 1 prepare signing ==== //
    
        console.log("\n");
        console.log(operationShell);
        console.log("\n");
    
        let { rawBytes, forgedOperationGroup } = await forge(operationShell); // ==== step 2 forging ==== //
    
        let signedBytes = await sign(rawBytes, secretKey, passphrase, salt, forgedOperationGroup)// ==== step 3 signing ==== //
    
        await injectOperation(signedBytes); // ==== step 4 inject signed bytes ==== //   
    } catch (e) {
        throw e;
    }
})();


