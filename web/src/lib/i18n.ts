import { computed, reactive } from "vue";

export type Locale = "zh" | "en";

const LOCALE_STORAGE = "etcat-web-locale-v1";

const messages = {
  en: {
    "app.subtitle": "Send files and messages between a browser and the CLI, end-to-end encrypted",
    "app.encrypted": "End-to-end encrypted via EasyTier — relays never see your data",
    "app.loading": "Loading the encryption runtime…",
    "app.loadFailed": "Failed to load the WebAssembly runtime",
    "nav.transfer": "Transfer",
    "nav.transferHint": "Files and messages",
    "nav.connections": "Connections",
    "conn.myListener": "My receive address",
    "conn.incoming": "incoming",
    "conn.outgoing": "outgoing",
    "workspace.sendTitle": "Send to a receiver",
    "workspace.sendHint": "Paste the link or token you were given",
    "workspace.receiveTitle": "Receive files & messages",
    "timeline.empty": "Transfers show up here",
    "timeline.earlier": "Earlier",
    "timeline.justNow": "just now",
    "timeline.minutesAgo": "m ago",
    "timeline.hoursAgo": "h ago",
    "tab.receive": "Receive",
    "tab.send": "Send",

    "receive.step1": "Start receiving",
    "receive.step2": "Share the link with the sender",
    "receive.step3": "Incoming transfers appear here",
    "receive.start": "Start receiving",
    "receive.starting": "Starting…",
    "receive.stop": "Stop",
    "receive.listening": "Receiving is on — keep this tab open",
    "receive.connecting": "Connecting to the relay…",
    "receive.failed": "Could not start receiving",

    "token.title": "Anyone with this link can send to you",
    "token.copyLink": "Copy link",
    "token.copyToken": "Copy token",
    "token.copied": "Copied!",
    "token.cliHint": "Or with the CLI:",

    "send.tokenLabel": "Receiver token or link",
    "send.tokenPlaceholder": "etc2… or paste the share link",
    "send.tokenInvalid": "This doesn't look like an etcat token or link",
    "send.dropHere": "Drop a file here, or click to browse",
    "send.fileSelected": "Ready to send — remove it to send text instead",
    "send.orText": "or write a message",
    "send.textPlaceholder": "Type a message…",
    "send.sendFile": "Send file",
    "send.sendText": "Send text",
    "send.sending": "Sending…",

    "transfer.sendTitle": "File",
    "transfer.sendTextTitle": "Message",
    "transfer.recvFileTitle": "Incoming file",
    "transfer.recvTextTitle": "Message received",
    "transfer.connecting": "Contacting receiver…",
    "transfer.transferring": "Transferring…",
    "transfer.confirming": "Waiting for the receiver to confirm…",
    "transfer.done": "Done",
    "transfer.failed": "Failed",
    "transfer.retry": "Retry",
    "transfer.copyText": "Copy",
    "transfer.textCopied": "Copied!",
    "transfer.saveFile": "Save file",
    "transfer.saving": "Saving…",
    "transfer.download": "Download",
    "transfer.tooLarge": "Payload too large to receive in the browser",
    "transfer.listenerStopped": "Receiving was stopped",
    "transfer.remove": "Remove",
    "transfer.clearDone": "Clear finished",

    "advanced.title": "Advanced settings",
    "advanced.relayUrl": "EasyTier WebSocket relay",
    "advanced.relayKey": "Relay public key (optional identity pin, base64)",
    "advanced.relayKeyPlaceholder": "optional",
    "advanced.persist": "Keep the same receiving address",
    "advanced.persistHint": "Stores the private listener key in this browser",

    "error.enterToken": "Paste the receiver's token or link first",
  },
  zh: {
    "app.subtitle": "浏览器与 CLI 之间互传文件和消息，端到端加密",
    "app.encrypted": "通过 EasyTier 端到端加密 —— 中继看不到你的数据",
    "app.loading": "正在加载加密运行时…",
    "app.loadFailed": "WebAssembly 运行时加载失败",
    "tab.receive": "接收",
    "tab.send": "发送",

    "receive.step1": "开始接收",
    "receive.step2": "把链接发给对方",
    "receive.step3": "收到的内容会出现在这里",
    "receive.start": "开始接收",
    "receive.starting": "正在启动…",
    "receive.stop": "停止接收",
    "receive.listening": "接收中 —— 请保持此标签页打开",
    "receive.connecting": "正在连接中继…",
    "nav.transfer": "传送",
    "nav.transferHint": "文件和消息",
    "nav.connections": "连接",
    "conn.myListener": "我的接收地址",
    "timeline.empty": "传输会出现在这里",
    "timeline.earlier": "更早",
    "timeline.justNow": "刚刚",
    "timeline.minutesAgo": " 分钟前",
    "timeline.hoursAgo": " 小时前",
    "conn.incoming": "传入",
    "conn.outgoing": "传出",
    "workspace.sendTitle": "发送给接收方",
    "workspace.sendHint": "粘贴对方给你的链接或接收码",
    "workspace.receiveTitle": "接收文件和消息",
    "receive.failed": "启动接收失败",

    "token.title": "任何拿到这个链接的人都能发给你",
    "token.copyLink": "复制链接",
    "token.copyToken": "复制接收码",
    "token.copied": "已复制！",
    "token.cliHint": "或者用命令行：",

    "send.tokenLabel": "对方的接收码或链接",
    "send.tokenPlaceholder": "etc2… 或粘贴分享链接",
    "send.tokenInvalid": "这看起来不是有效的接收码或链接",
    "send.dropHere": "把文件拖到这里，或点击选择",
    "send.fileSelected": "已选择文件，发送前可点 × 移除以改发文字",
    "send.orText": "或者写一段文字",
    "send.textPlaceholder": "输入消息…",
    "send.sendFile": "发送文件",
    "send.sendText": "发送文字",
    "send.sending": "发送中…",

    "transfer.sendTitle": "文件",
    "transfer.sendTextTitle": "消息",
    "transfer.recvFileTitle": "收到文件",
    "transfer.recvTextTitle": "收到消息",
    "transfer.connecting": "正在联系接收方…",
    "transfer.transferring": "传输中…",
    "transfer.confirming": "等待对方确认…",
    "transfer.done": "完成",
    "transfer.failed": "失败",
    "transfer.retry": "重试",
    "transfer.copyText": "复制",
    "transfer.textCopied": "已复制！",
    "transfer.saveFile": "保存文件",
    "transfer.saving": "保存中…",
    "transfer.download": "下载",
    "transfer.tooLarge": "内容过大，无法在浏览器中接收",
    "transfer.listenerStopped": "接收已停止",
    "transfer.remove": "移除",
    "transfer.clearDone": "清除已完成",

    "advanced.title": "高级设置",
    "advanced.relayUrl": "EasyTier WebSocket 中继",
    "advanced.relayKey": "中继公钥（可选，用于固定身份，base64）",
    "advanced.relayKeyPlaceholder": "可选",
    "advanced.persist": "保持相同的接收地址",
    "advanced.persistHint": "会把监听私钥保存在此浏览器中",

    "error.enterToken": "请先粘贴对方的接收码或链接",
  },
} as const;

export type MessageKey = keyof (typeof messages)["en"];

function initialLocale(): Locale {
  const params = new URLSearchParams(window.location.search);
  const forced = params.get("lang");
  if (forced === "zh" || forced === "en") return forced;
  const stored = window.localStorage.getItem(LOCALE_STORAGE);
  if (stored === "zh" || stored === "en") return stored;
  return navigator.language.toLowerCase().startsWith("zh") ? "zh" : "en";
}

const state = reactive<{ locale: Locale }>({ locale: initialLocale() });

export function setLocale(locale: Locale): void {
  state.locale = locale;
  window.localStorage.setItem(LOCALE_STORAGE, locale);
}

export function useI18n() {
  const locale = computed(() => state.locale);
  const t = (key: MessageKey): string => messages[state.locale][key];
  return { locale, setLocale, t };
}
