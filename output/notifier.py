"""
Notification sender for Telegram alerts.
Uses only urllib (zero dependencies).
"""
import urllib.request
import urllib.parse
import json
import logging

log = logging.getLogger(__name__)


class TelegramNotifier:
    """Send notifications via Telegram Bot API."""

    API_URL = "https://api.telegram.org/bot{token}/sendMessage"

    def __init__(self, bot_token, chat_id):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.enabled = bool(bot_token and chat_id)

    def send(self, message):
        """Send a message via Telegram. Returns True on success."""
        if not self.enabled:
            return False

        try:
            url = self.API_URL.format(token=self.bot_token)
            data = urllib.parse.urlencode({
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }).encode()

            req = urllib.request.Request(url, data=data)
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
                if result.get('ok'):
                    log.info("📱 Telegram notification sent.")
                    return True
                else:
                    log.warning(f"Telegram API error: {result}")
                    return False
        except Exception as e:
            log.warning(f"Failed to send Telegram notification: {e}")
            return False

    def notify_active(self, target_type, raw_line, details=None):
        """Send an active IPTV service notification."""
        detail_lines = ""
        if details:
            for key, value in details.items():
                detail_lines += f"  • {key}: <code>{value}</code>\n"

        msg = (f"📺 <b>ACTIVE IPTV FOUND!</b>\n\n"
               f"🏷️ Type: <code>{target_type.upper()}</code>\n"
               f"🔗 Target: <code>{raw_line[:100]}</code>\n")
        if detail_lines:
            msg += f"\n📋 Details:\n{detail_lines}"
        msg += f"\n✅ IPTV Checker - Active Service Found"
        return self.send(msg)

    def notify_complete(self, total, checked, active, expired):
        """Send a completion notification."""
        msg = (f"📊 <b>IPTV Check Complete</b>\n\n"
               f"🔢 Total: {total}\n"
               f"✅ Checked: {checked}\n"
               f"📺 Active: {active}\n"
               f"⏰ Expired: {expired}\n\n"
               f"IPTV Checker - Complete")
        return self.send(msg)

    def notify_abort(self, reason):
        """Send an abort notification."""
        msg = (f"🛑 <b>IPTV Check Aborted</b>\n\n"
               f"⚠️ Reason: {reason}\n\n"
               f"IPTV Checker - Aborted")
        return self.send(msg)
