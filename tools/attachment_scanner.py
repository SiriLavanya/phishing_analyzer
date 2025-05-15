import hashlib
def get_attachment_hashes(attachments):
    if not attachments:
        return []
    return [f"{name}: {hashlib.sha256(data).hexdigest()}" for name, data in attachments]
