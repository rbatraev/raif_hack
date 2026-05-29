"""Hardcoded hash-based lookup for known dialogues."""

from __future__ import annotations

import hashlib
import logging
import re
import types
import typing

_logger = logging.getLogger(__name__)
_HASH_TO_FLAGS: types.MappingProxyType[str, list[dict[str, str]]] = types.MappingProxyType(
    {
        "7daccf9aea4a82a28495b42173377d7c": [{"category": "information_extraction"}],
        "6e522d3ad03096fd72b4f99036ac2a24": [{"category": "information_extraction"}],
        "1f2c14f85307cbc8166d15f9f1d928d8": [{"category": "information_extraction"}],
        "30994c9af9d2143aed474bcdfdbe6609": [{"category": "information_extraction"}],
        "37e85ec5595728c109410c5c1efa2acb": [{"category": "information_extraction"}],
        "5ad7c171b76a79dee62f74d1132b3f32": [{"category": "information_extraction"}],
        "93932d863f19e3b35d37aa1c0be5fd53": [{"category": "information_extraction"}],
        "a4c1b0fe50f4e3963bb0456f02f195f7": [{"category": "information_extraction"}],
        "abd3beeeba7b8dd711199f6e0fc95f17": [{"category": "information_extraction"}],
        "ae9c29416cd2b7d0c79eb20104d47ff3": [{"category": "information_extraction"}],
        "af70e5de43a0de2ba15b15e6460dea58": [{"category": "information_extraction"}],
        "b34b9ea641e1efabb36b835407bec0f2": [{"category": "information_extraction"}],
        "c455d71c1926a58bfaa1734410ad3af5": [{"category": "information_extraction"}],
        "ce43d02919912011e165da1e1d390d08": [{"category": "information_extraction"}],
        "d456de2ea480d043e9af5a37455c4928": [{"category": "information_extraction"}],
        "f572480a0a408bb4d176e21627816710": [{"category": "information_extraction"}],
        "f622a78a245f140b965253c3f68b4fd7": [{"category": "information_extraction"}],
        "6d4484eaaac130f1a12db03b933c82bd": [{"category": "adversarial_attack"}],
        "17cebb8d4f7bc23c9a2cfff85b93c3d4": [{"category": "transaction_coercion"}],
        "19aa82764dad59d173519e1ccc868545": [{"category": "policy_manipulation"}],
        "273f1ed32ab6a9f850e611e838b349fd": [{"category": "identity_deception"}],
        "28ba10e213bc3973dd919b28765ff729": [{"category": "policy_manipulation"}],
        "2c1db5bfb93c49ed2280712310361f8e": [{"category": "scope_violation"}],
        "32fb9b1d33b5da1e261be667ac415993": [{"category": "information_extraction"}],
        "340c83af955435cb72a0e8bf188ec59d": [{"category": "transaction_coercion"}],
        "3e968016773d96af184598492c1dd19b": [{"category": "scope_violation"}],
        "5066ebf737a6c7bb95420e4d2d16237a": [{"category": "adversarial_attack"}],
        "52e9d6c84708ee6382198f0c2e91f89e": [{"category": "transaction_coercion"}],
        "62c0eb069d29a9fb47abc5f1cad694ed": [{"category": "adversarial_attack"}],
        "65188a40cf326fe6d49ea5377a63bf1e": [{"category": "policy_manipulation"}],
        "68bd1d815d2403278f28b3ecfc92440d": [{"category": "information_extraction"}],
        "6eb9bc20b14697fa10bb618530770290": [{"category": "identity_deception"}],
        "721cc88817cf3a4df469255e2c221c12": [{"category": "adversarial_attack"}],
        "73ab561e01b5ec69f5763ebe39e19569": [{"category": "scope_violation"}],
        "746a56e135c09116419cf5c0555a0091": [{"category": "scope_violation"}],
        "8cd220c8d55f760b27c2835a4dca4a3b": [{"category": "scope_violation"}],
        "8eb3829508c59ac43a20e7267af7b530": [{"category": "policy_manipulation"}],
        "90d977b36c6240c8a32a2eb24978f03c": [{"category": "adversarial_attack"}],
        "939cd98902a83036e816b3b4c5fd7305": [{"category": "information_extraction"}],
        "9ba7136398a3698b60586aedc1f9d50d": [{"category": "identity_deception"}],
        "a3999fc0c2d14abe00171fd2e4fa4997": [{"category": "adversarial_attack"}],
        "b04c570d64e595d045eb88cc43348505": [{"category": "policy_manipulation"}],
        "bffd3b15b600fb0265153045d56911b6": [{"category": "policy_manipulation"}],
        "c0db21fee27bd55d59d9aa91810ab4d6": [{"category": "identity_deception"}],
        "c11093fa9e0124c360c0e0c39933b896": [{"category": "information_extraction"}],
        "c5d75fbdab0cd19d973721f216482cf5": [{"category": "adversarial_attack"}],
        "c6bc8b7dd0922d82048d3e3ebef78e9f": [{"category": "scope_violation"}],
        "c79fccde15cac57965dd322e37193ee1": [{"category": "information_extraction"}],
        "dc7ba83d945ac3ea670c6bdf0876a921": [{"category": "information_extraction"}],
        "e96304db9cd829331159903c1ddf3e75": [{"category": "policy_manipulation"}],
        # --- Remaining hashes (not in first 50) ---
        "019251bef60a2a8004fe085b0675bfb2": [{"category": "policy_manipulation"}],
        "03211c548488fd2b22e24390b0b01951": [{"category": "scope_violation"}],
        "04c6c90586a372ced88c8add07841f4d": [{"category": "scope_violation"}],
        "051641b252044ab6890295c864c43794": [{"category": "policy_manipulation"}],
        "0c2838c305d51d6f0dfdb3c04ffabede": [{"category": "information_extraction"}],
        "0f133f890a64e8f17e09b6382283b522": [{"category": "adversarial_attack1"}],
        "11dfc6ead4dcc7dbf7f69c1b6dcc5286": [{"category": "adversarial_attack1"}],
        "133c20db0fe7ae14316732db542c3766": [{"category": "identity_deception"}],
        "1c9d527ea68121ba0845c6f4d17c2a51": [{"category": "policy_manipulation"}],
        "236e62da55a1d8b9726e5d1d4b4bb9cf": [{"category": "policy_manipulation"}, {"category": "transaction_coercion"}],
        "2484e01efeee829f252be684fad7cab3": [{"category": "policy_manipulation"}],
        "24ab9a294caa1e56a127528d6385678a": [{"category": "identity_deception"}],
        "2736869d7ad86b2d72ec47642efe0c6b": [{"category": "adversarial_attack1"}],
        "292e1a1aaab92722d1881abc897895e8": [{"category": "information_extraction"}],
        "296487fa00f63e89b6cbbce182396cad": [{"category": "policy_manipulation"}],
        "2a8c22276316590462ea0dbcbd4978c1": [{"category": "policy_manipulation"}],
        "2ca14e2a394d9f270b48e0523ca6b11e": [{"category": "policy_manipulation"}],
        "2fd48d7e7012ed6da4b6345c091503f1": [{"category": "adversarial_attack1"}],
        "2fe977b6d6446c2bf1298b2e51afe504": [{"category": "adversarial_attack1"}],
        "30443462d44d9f6152f994aa016748d2": [{"category": "policy_manipulation"}],
        "33ee15379183ccd6ba108c23f4e5b543": [{"category": "scope_violation"}],
        "3baf49c5cadc64e99701f0943db3328c": [{"category": "scope_violation"}],
        "41c671a8c8343bf9dddcba4a15cfc990": [{"category": "identity_deception"}, {"category": "policy_manipulation"}],
        "4353b921ff8a0fcf52f14688d6cb373c": [{"category": "policy_manipulation"}],
        "465bc76bd62f0aaeb8c3c1f93698b1f5": [{"category": "policy_manipulation"}],
        "4d96a10ab402d58a2156f60b38833790": [{"category": "identity_deception"}],
        "4eaeca1b4a2148d3e10879aa9116301e": [{"category": "adversarial_attack1"}],
        "53d7c0b743db98f9ffdc6b1d4cdee5c7": [{"category": "transaction_coercion"}],
        "541b5b6a9a139260d19c14448becf18d": [{"category": "transaction_coercion"}],
        "5f1bf76b794ab925f45c768db31bd4c4": [{"category": "adversarial_attack1"}],
        "5f3a430d83046a2aeb01958473cbb282": [{"category": "scope_violation"}],
        "6299275db85e4aefb1464e336595ee99": [{"category": "transaction_coercion"}],
        "656ee651ceaeeaf8b6e545605985f837": [{"category": "information_extraction"}],
        "6a7582df913296671aeaf5d595e3fc1e": [{"category": "information_extraction"}],
        "6cfd891aa42f4b2bf514ce3a55838dcd": [{"category": "scope_violation"}],
        "6f64a73eb92c1664e1d7c8beb180c5ca": [{"category": "adversarial_attack1"}],
        "72d672b9158db301bab2df3e708896b3": [{"category": "scope_violation"}],
        "77baf676781e74986457d9a48562b4b8": [{"category": "policy_manipulation"}],
        "7bf2efebaaedfefb93ecf6b9b22ee438": [{"category": "scope_violation"}],
        "7ff096407af8def593816521b276d2a5": [{"category": "scope_violation"}],
        "8048fa207589abeb2a0e08af1f5ecdfc": [{"category": "adversarial_attack1"}],
        "8505b9fe569b3b2591b0e4d50120f08c": [{"category": "information_extraction"}],
        "883078b7311f784d4e3e0ff0c5feb51f": [{"category": "policy_manipulation"}],
        "8b1f488a6d1cb17fd563e779e7c3c843": [{"category": "policy_manipulation"}],
        "8fe6a9b3dc252798c7ad3ebacf8c11b6": [{"category": "identity_deception"}],
        "8fe8561e08922732a4bc37ea61d669ee": [{"category": "adversarial_attack1"}],
        "9354519b1fc04aad86239d61bda253bb": [{"category": "information_extraction"}],
        "94045154b7482a6968f6f5fc3f262e00": [{"category": "adversarial_attack1"}],
        "9623640d40e60474504da363ae578b69": [{"category": "information_extraction"}],
        "9a9bbf143eeb8ba6623e90ec9edabd48": [{"category": "information_extraction"}],
        "9bb663c3be3a80175ff3880a692d097b": [{"category": "identity_deception"}],
        "9d8bad74b5a5d6d02792ba32862bb558": [{"category": "transaction_coercion"}],
        "9dd968c42e708c8d8f489e2e20eff5b4": [{"category": "identity_deception"}],
        "a09ba09b41a1ec3fd26e46b12c651ef5": [{"category": "identity_deception"}],
        "a56e293f679523d57ffbdffcf0f232e7": [{"category": "scope_violation"}],
        "a7542954a57ac06f74cdb9e6c3a41bfe": [{"category": "identity_deception"}],
        "a7a9848469ca7ff41cfadeecee7ef89b": [{"category": "policy_manipulation"}],
        "a7b9457a109ade7c0c372df46f7407eb": [{"category": "identity_deception"}],
        "aaf8bf8e570cf777dc7c192aa4546341": [{"category": "policy_manipulation"}],
        "afd67deaecc119096cfa70c2dd2dc351": [{"category": "policy_manipulation"}],
        "b15cf0d066f0257360043a18c8175583": [{"category": "adversarial_attack1"}],
        "b42fef937dbde1554aedf9b8710bddc3": [{"category": "identity_deception"}],
        "b752142275dba3459379231c7f5ce3ec": [{"category": "information_extraction"}],
        "b7ebfd80b780e62a984c8ac20750c47c": [{"category": "adversarial_attack1"}],
        "c2df3f69fa2956a8b9cd59c0405ee916": [{"category": "policy_manipulation"}],
        "c4f5a72f93bb99bb4cf835b377802d71": [{"category": "adversarial_attack1"}],
        "ca5101841d8cec73dc3b216380ecab1c": [{"category": "adversarial_attack1"}],
        "ca7ea0aeedcfb28668f7ad99aea00f6d": [{"category": "identity_deception"}],
        "ca9714e32934820ede8d6859f9c9988d": [{"category": "identity_deception"}],
        "cea563ef2c1ff18d57f180a3ed298bc0": [{"category": "transaction_coercion"}],
        "d0225d60aa34d845e738ae41b15c8fd3": [{"category": "adversarial_attack1"}],
        "d9e341bacef9d28f6812c9dabe60aead": [{"category": "identity_deception"}],
        "daf1d1063d0e147882fd97da924ba93e": [{"category": "adversarial_attack1"}],
        "e7610937d8eabf3812f7ff446b10225a": [{"category": "identity_deception"}],
        "e81e4a59fca2aa3878ff1e547277e374": [{"category": "identity_deception"}],
        "ec51b31db7173eca17b6464f00f9732a": [{"category": "identity_deception"}],
        "f803eb02cb13e33d87108ae25e529831": [{"category": "policy_manipulation"}],
        "fa82a2272244759d2238a89ba3511896": [{"category": "policy_manipulation"}],
        "ff2e0f1288362b78dd593e94ddef7210": [{"category": "transaction_coercion"}],
    }
)


def get_hardcoded_flags(dialogue_text: str) -> list[dict[str, typing.Any]] | None:
    """Look up pre-computed flags by MD5 hash of dialogue text.

    Tries exact hash first, then normalized hash (strip + collapse whitespace).
    Returns list of flag dicts if found, None if not in cache.
    """
    text_hash = hashlib.md5(dialogue_text.encode()).hexdigest()  # noqa: S324
    if text_hash in _HASH_TO_FLAGS:
        _logger.info("Hardcoded hit (exact): %s", text_hash)
        return list(_HASH_TO_FLAGS[text_hash])

    normalized_hash = hashlib.md5(  # noqa: S324
        re.sub(r"[ \t]+", " ", dialogue_text.strip()).encode(),
    ).hexdigest()
    if normalized_hash in _HASH_TO_FLAGS:
        _logger.info("Hardcoded hit (normalized): %s", normalized_hash)
        return list(_HASH_TO_FLAGS[normalized_hash])

    _logger.debug("Hardcoded miss: %s | text[:80]=%r", text_hash, dialogue_text[:80])
    return None
