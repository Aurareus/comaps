"""NIP-01 events: canonical serialization, id, BIP-340 signature."""

import json
from dataclasses import dataclass, field

from . import primitives as p

_ESCAPES = {'\n': '\\n', '"': '\\"', '\\': '\\\\', '\r': '\\r', '\t': '\\t', '\b': '\\b', '\f': '\\f'}


def _json_string(s: str) -> str:
    """NIP-01 string escaping: only the 7 listed characters are escaped, all others verbatim."""
    return '"' + ''.join(_ESCAPES.get(c, c) for c in s) + '"'


def serialize(pubkey_hex: str, created_at: int, kind: int, tags: list, content: str) -> bytes:
    tags_json = '[' + ','.join('[' + ','.join(_json_string(v) for v in tag) + ']' for tag in tags) + ']'
    text = '[0,' + _json_string(pubkey_hex) + ',' + str(created_at) + ',' + str(kind) + ',' + tags_json + ',' + \
        _json_string(content) + ']'
    return text.encode('utf-8')


@dataclass
class Event:
    pubkey: str
    created_at: int
    kind: int
    tags: list = field(default_factory=list)
    content: str = ''
    id: str = ''
    sig: str = ''

    def compute_id(self) -> str:
        return p.sha256(serialize(self.pubkey, self.created_at, self.kind, self.tags, self.content)).hex()

    def sign(self, sk: bytes, aux32: bytes) -> 'Event':
        if p.secp_xonly_pub(sk).hex() != self.pubkey:
            raise ValueError('pubkey does not match secret key')
        self.id = self.compute_id()
        self.sig = p.schnorr_sign(sk, bytes.fromhex(self.id), aux32).hex()
        return self

    def verify(self) -> bool:
        if self.compute_id() != self.id:
            return False
        return p.schnorr_verify(bytes.fromhex(self.pubkey), bytes.fromhex(self.id), bytes.fromhex(self.sig))

    def tag_value(self, name: str):
        for tag in self.tags:
            if len(tag) >= 2 and tag[0] == name:
                return tag[1]
        return None

    def to_dict(self) -> dict:
        return {'id': self.id, 'pubkey': self.pubkey, 'created_at': self.created_at, 'kind': self.kind,
                'tags': self.tags, 'content': self.content, 'sig': self.sig}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(',', ':'), ensure_ascii=False)

    @staticmethod
    def from_dict(d: dict) -> 'Event':
        return Event(pubkey=d['pubkey'], created_at=d['created_at'], kind=d['kind'], tags=d['tags'],
                     content=d['content'], id=d['id'], sig=d['sig'])
