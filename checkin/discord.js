import axios from 'axios';
import dotenv from "dotenv";
dotenv.config({ path: ".env" });

const webhookUrl = process.env.DISCORD_WEBHOOK_URL;

export const sendMessage = async (message) => {
    if (!webhookUrl) {
        console.log('Discord Webhook URL 未配置');
        return;
    }
    try {
        await axios.post(webhookUrl, message);
    } catch (error) {
        console.error('发送消息到 Discord Webhook 失败：', error);
    }
};

export default {
    sendMessage,
};

