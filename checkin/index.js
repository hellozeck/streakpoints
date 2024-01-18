import Web3 from 'web3';
import axios from 'axios';
import dotenv from 'dotenv';
import contractAbi from './checkin.json' assert { type: "json" };
import fs from 'fs';
import { sendMessage } from './discord.js';

dotenv.config();

console.log('INFURA_URL:', process.env.INFURA_URL);
const web3 = new Web3();
const provider = new web3.providers.HttpProvider(process.env.INFURA_URL);
web3.setProvider(provider);
const contractAddress = '0xfb86e23C71EcfD07AF371B290a453704F52B1f9A';
const contract = new web3.eth.Contract(contractAbi, contractAddress);

async function getCode() {
    try {
        const response = await axios.get('https://streakpoints.com/-/api/login-nonce');
        // console.log('Headers:', headers);
        const code = response.data.results;
        const headers = response.headers;
        const setCookieHeader = headers['set-cookie'][0];
        // 使用正则表达式提取 connect.sid 的值
        const regex = /connect\.sid=([^;]+)/;
        const match = setCookieHeader.match(regex);
        const connectSid = match ? match[1] : null;

        const expiresMatch = setCookieHeader.match(/Expires=([^;]+)/);
        let expiresTimestamp = 0;
        if (expiresMatch) {
            const expiresValue = expiresMatch[1];
            console.log('Expires:', expiresValue);
            // 转换为时间戳
            expiresTimestamp = Date.parse(expiresValue);
        } else {
            console.log('Expires not found in the Set-Cookie header');
        }
        return { code, connectSid, expiresTimestamp };

    } catch (error) {
        console.error('Error fetching code:', error);
        throw error;
    }
}

async function signMessage(privateKey, code) {
    try {
        const message = 'Signing in to StreakPoints. Code: ';
        const completeMessage = message + code;
        const signature = web3.eth.accounts.sign(completeMessage, privateKey);
        return signature.signature;
    } catch (error) {
        console.error('Error signing message:', error);
        throw error;
    }
}

async function getAccountIsCheckedIn(address) {
    try {
        const result = await contract.methods.getAccountIsCheckedIn(address).call();
        return Boolean(result);
    } catch (error) {
        console.error('Error getting account checked in status:', error);
        throw error;
    }
}


async function checkin(epoch, referrer, signature, privateKey, walletAddress) {
    try {
        const gasLimit = await contract.methods.checkin(epoch, referrer, signature).estimateGas({ from: walletAddress });
        const gasPrice = await web3.eth.getGasPrice();
        console.log('Gas estimate:', gasLimit);
        console.log('Gas price:', gasPrice);

        const txObject = {
            from: walletAddress,
            to: contractAddress,
            gasLimit: gasLimit,
            gasPrice: gasPrice,
            data: contract.methods.checkin(epoch, referrer, signature).encodeABI(),
        };

        const signedTx = await web3.eth.accounts.signTransaction(txObject, privateKey);
        const receipt = await web3.eth.sendSignedTransaction(signedTx.rawTransaction);

        console.log('Receipt:', receipt);
    } catch (error) {
        console.error('Error calling Checkin:', error);
        throw error;
    }
}

// 通过私钥获得钱包地址
function getAddress(privateKey) {
    const account = web3.eth.accounts.privateKeyToAccount(privateKey);
    return account.address;
}

async function verifyCheckin(headers) {
    const url = 'https://streakpoints.com/-/api/checkin/verify';

    try {
        const response = await axios.get(url, {
            headers: headers,
            timeout: 10000, // Set timeout to 10 seconds
        });
        console.log('Verify response:', response.data);
        return response.data;
    } catch (error) {
        console.error('Error:', error);
    }
}

async function login(address, signature, headers) {
    const url = "https://streakpoints.com/-/api/login";
    try {
        const response = await axios.post(url, {
            address: address,
            signature: signature,
        }, {
            headers: headers,
        });
        const data = response.data;
        console.log('Login response:', data);
    } catch (error) {
        console.error('Error:', error);
    }
}

async function main() {
    try {
        const referrer = "0xcD01A3acED67e266be21117376C7025B384Cd4d7";
        const privateKeyList = fs.readFileSync('privateKeyList.csv', 'utf8').split('\n');
        if (privateKeyList[privateKeyList.length - 1] === '') {
           privateKeyList.pop();
         }
        console.log(privateKeyList.length);

        const getCodeResultMap = new Map();

        while (true) {
            for (let i = 0; i < privateKeyList.length; i++) {
                const privateKey = privateKeyList[i];
                const walletAddress = getAddress(privateKey);

                const today = new Date();
                const message = {
                    content: `已签到：${walletAddress} - ${today}`,
                };

                try {
                    const isCheckedIn = await getAccountIsCheckedIn(walletAddress);
                    if (isCheckedIn === true) {
                        console.log('Already checked in:', walletAddress);
                        await sendMessage(message);
                        continue;
                    }

                    let getCodeResult = undefined;
                    if (getCodeResultMap.has(privateKey)) {
                        getCodeResult = getCodeResultMap.get(privateKey);
                        const expiresTimestamp = getCodeResult.expiresTimestamp;
                        const currentTimestamp = Date.now();
                        if (currentTimestamp >= expiresTimestamp) {
                            getCodeResult = await getCode();
                            getCodeResultMap.set(privateKey, getCodeResult);
                        }
                    } else {
                        getCodeResult = await getCode();
                        getCodeResultMap.set(privateKey, getCodeResult);
                    }

                    const code = getCodeResult.code;
                    const connectSid = getCodeResult.connectSid;

                    const headers = {
                        'Cookie': `connect.sid=${connectSid}`
                    };
                    const signature = await signMessage(privateKey, code);
                    await login(walletAddress, signature, headers);
                    const verifyResults = await verifyCheckin(headers);
                    const currentEpoch = verifyResults.results.currentEpoch;
                    const verification = verifyResults.results.verification;
                    console.log('ready to checkint walletAddress:', walletAddress);
                    await checkin(currentEpoch, referrer, verification, privateKey, walletAddress);
                    await sendMessage(message);
                } catch (error) {
                    console.error('Error:', error);
                }
            }
            // 12小时检查一次
            await new Promise(resolve => setTimeout(resolve, 3600000 * 12));
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

main();
