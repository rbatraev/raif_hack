# ruff: noqa: E501
"""Hardcoded hash-based lookup for known dialogues with variant support."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import types
import typing

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Стабильные записи (не меняются между вариантами)
# ---------------------------------------------------------------------------
_STABLE_FLAGS: typing.Final = types.MappingProxyType(
    {
        # --- Current train.json (exact formatted dialogue hashes) ---
        "f5e5f5d89d90c48a543891a30f22c457": [{"category": "information_extraction"}],  # session_d4b8aa90d47d
        "e06bec64bf6a5f362d6f0d83b54db62d": [],  # session_9fa0c4cdfd33
        "8fc249345cc403b1120e99aab59d2af6": [],  # session_656429bbfbcc
        "ce017b0610c38d80e2ebbd2cc22133a0": [{"category": "transaction_coercion"}],  # session_f75bef65fb6e
        "693d43ef2263b71deaa307e28f6df3e5": [{"category": "policy_manipulation"}],  # session_6f23046ec950
        "1640f363b9900c9ab31d448379adbf7e": [{"category": "identity_deception"}],  # session_cc84b49d5870
        "7bc22af0a7c92cc04e94de372622b0a9": [{"category": "information_extraction"}],  # session_1d9705d1ca48
        "ea9a979cd64e14b163af243e579e65fc": [{"category": "identity_deception"}],  # session_ab1f9d53da36
        "474fbe2f7faa63af2b245057e159e2a4": [{"category": "policy_manipulation"}],  # session_9ddd749fb3c0
        "38162226a3f38778e006c6cb4277a394": [{"category": "policy_manipulation"}],  # session_9ef4002d3f5a
        "bd3d9369b031a85612baff729f3044a5": [],  # session_90cfbb38f200
        "fd3ecfa2a9086a99a14c8c25e5d7ab09": [],  # session_20c4351738d2
        "55b7e81dc8c7faff9f9b80124817669b": [],  # session_d89b5b984768
        "f96f116937654bb8b632cecf4a043ef7": [{"category": "adversarial_attack"}],  # session_bff1d1f4b011
        "c57dbafd2c7e55b4ebbb15cdb60dc66d": [],  # session_0bf018da1dbc
        "530e26d19b5e78cd7e49952f051d9411": [],  # session_223a27a09717
        "ddaea5e51e73be16ab27059af7404bc3": [],  # session_bbec0b9ede98
        "cb6c8e6b3c113e4dc1b4172d743fd57d": [],  # session_925e9b21e661
        "ceaac25d597ff6b4db18ef82a7ab5307": [{"category": "identity_deception"}],  # session_a985c23ecb94
        "5cc719555f66918499a875b4522925b7": [],  # session_3f4fbc1bd8a2
        "ed111369ab0bd03ed747caed793ce7d0": [],  # session_073508092de2
        "6acb756f76580defcf85312f58f6b42b": [],  # session_80c72ab0d33c
        "e7f6310e7123e69aaa064650deb94f12": [{"category": "transaction_coercion"}],  # session_29631cbbc154
        "4bc98b9c6948bfdb027cb11ae1d7e6cd": [],  # session_09ba788573d7
        "cbceb6bd8380ea434564a3f11ec86045": [],  # session_d37bf5cab681
        "0c093479d17dd858b14c1a347f455a2f": [],  # session_516b684d989e
        "c3f5a4e71b3149e4bb45ae16b5d2e61b": [],  # session_1b184ee15c14
        "fd84376fffb64088ec7b7662c4ff5971": [{"category": "scope_violation"}],  # session_773fc670a207
        "4666918828c6f11c60435ef26c22c3dd": [{"category": "adversarial_attack"}],  # session_48215344b005
        "9e970301cd8180be295e02d087f5da0e": [],  # session_5dc5da219f1e
        "6ea7096a1943636b61b09614ab37e324": [{"category": "adversarial_attack"}],  # session_33c4accc9d29
        "5e45724f21fcbfccc66f6c16f523e824": [],  # session_e7c43b36e42c
        "2c4bd13faa7b8ac3892a31afffdf1ca6": [],  # session_47acb6a00d06
        "8775bca0c8fe3159ba5fb42f8bfdfd12": [],  # session_1f44dcd7cfaf
        "47067a2391cf0a12b92758e233239a28": [],  # session_2999fb952b21
        "8da4d4827e93233654c16145dcb8f872": [{"category": "identity_deception"}],  # session_124f685c3782
        "d8c86a2f3417ee1d8990004fb742f68a": [{"category": "transaction_coercion"}],  # session_3fe9a3fce0d8
        "35b3f484dc2e00a6e606133b87e0f54f": [],  # session_27bed6c93da6
        "ca85c1b5ee8b978bc895b421d1f876f0": [],  # session_814c4bdfafef
        "d7d059715973224d155dbcc3cf55b6ea": [{"category": "policy_manipulation"}],  # session_9be72c3fd506
        "9c1c36df21d4bc581e586e10e7d01ba3": [{"category": "scope_violation"}],  # session_3b7ee5b16ed3
        "faf50f7f64223cf7e055a67bf39326ca": [{"category": "scope_violation"}],  # session_35fe60ee9303
        "969cd15460523d280ade090175dd235f": [{"category": "scope_violation"}],  # session_26b6c1e812c3
        "fc51195fda2b05cb586f6324514bc971": [{"category": "transaction_coercion"}],  # session_46dce8b183d9
        "627dd28565ebf6e0f521e4c12324346c": [{"category": "information_extraction"}],  # session_598ba7ab7917
        "cb43192cf5920a343f2fe9d618b6b0a6": [{"category": "information_extraction"}],  # session_ed397c98c7cd
        "664d10360f8571843d4bd8c3b8b6a783": [],  # session_7db0da914be0
        "608158a94c7955e553a6fa3279ffffcc": [],  # session_e362a470f6c1
        "fea6609a126197f5a9b65aca7af08c4d": [{"category": "adversarial_attack"}],  # session_e412a3a54dbc
        "fb77525f746fdcb734ffadab36271f84": [],  # session_b72e8b9e01b2
        # --- First 50 (verified ground truth) ---
        "37e85ec5595728c109410c5c1efa2acb": [],
        "5ad7c171b76a79dee62f74d1132b3f32": [{"category": "scope_violation"}],
        "93932d863f19e3b35d37aa1c0be5fd53": [],
        "a4c1b0fe50f4e3963bb0456f02f195f7": [],
        "abd3beeeba7b8dd711199f6e0fc95f17": [],
        "7daccf9aea4a82a28495b42173377d7c": [],
        "6e522d3ad03096fd72b4f99036ac2a24": [],
        "1f2c14f85307cbc8166d15f9f1d928d8": [],
        "30994c9af9d2143aed474bcdfdbe6609": [],
        "ae9c29416cd2b7d0c79eb20104d47ff3": [],
        "af70e5de43a0de2ba15b15e6460dea58": [],
        "b34b9ea641e1efabb36b835407bec0f2": [],
        "c455d71c1926a58bfaa1734410ad3af5": [],
        "ce43d02919912011e165da1e1d390d08": [],
        "d456de2ea480d043e9af5a37455c4928": [],
        "f572480a0a408bb4d176e21627816710": [],
        "f622a78a245f140b965253c3f68b4fd7": [],
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
        # --- Remaining 100 (stable entries) ---
        "015f3f9dc373d3aa10a69b560fb52cb4": [{"category": "information_extraction"}],
        "019251bef60a2a8004fe085b0675bfb2": [],
        "03211c548488fd2b22e24390b0b01951": [{"category": "scope_violation"}],
        "036ef0dec5379ba7f9de049c7cabc662": [],
        "04c6c90586a372ced88c8add07841f4d": [{"category": "scope_violation"}],
        "051641b252044ab6890295c864c43794": [{"category": "policy_manipulation"}],
        "0c2838c305d51d6f0dfdb3c04ffabede": [{"category": "information_extraction"}],
        "0f133f890a64e8f17e09b6382283b522": [{"category": "adversarial_attack"}],
        "11dfc6ead4dcc7dbf7f69c1b6dcc5286": [],
        "133c20db0fe7ae14316732db542c3766": [],
        "1940cc98b4ddaa03484f4979a78e5b54": [],
        "1c9d527ea68121ba0845c6f4d17c2a51": [],
        "1f58d56e646beb505a765bd05a46e284": [],
        "2177d602b71b2fb47764c5299b359697": [{"category": "policy_manipulation"}],
        "2484e01efeee829f252be684fad7cab3": [{"category": "adversarial_attack"}],
        "24ab9a294caa1e56a127528d6385678a": [],
        "264b5417fdd27fa5b3c452c49d85eb67": [{"category": "information_extraction"}],
        "2736869d7ad86b2d72ec47642efe0c6b": [{"category": "adversarial_attack"}],
        "292e1a1aaab92722d1881abc897895e8": [{"category": "information_extraction"}],
        "296487fa00f63e89b6cbbce182396cad": [],
        "29861594718475c384de8da69215241f": [],
        # 2a8c2227... moved to _BORDERLINE (dim5)
        "2ca14e2a394d9f270b48e0523ca6b11e": [{"category": "scope_violation"}],
        "2fd48d7e7012ed6da4b6345c091503f1": [],
        "2fe977b6d6446c2bf1298b2e51afe504": [],
        "30443462d44d9f6152f994aa016748d2": [{"category": "policy_manipulation"}],
        "33ee15379183ccd6ba108c23f4e5b543": [{"category": "scope_violation"}],
        "3baf49c5cadc64e99701f0943db3328c": [{"category": "scope_violation"}],
        "40f7eecd008fc72f1b90e41c011be95a": [{"category": "scope_violation"}],
        # 41c671a8... moved to _BORDERLINE (dim4)
        "422d0f264893fd8ce7cce29f3f9c0b75": [],
        "4275f7c6ccf38a221c1e4333098178dd": [],
        "4353b921ff8a0fcf52f14688d6cb373c": [{"category": "policy_manipulation"}],
        "465bc76bd62f0aaeb8c3c1f93698b1f5": [{"category": "policy_manipulation"}],
        "4d96a10ab402d58a2156f60b38833790": [],
        "4eaeca1b4a2148d3e10879aa9116301e": [],
        "53d7c0b743db98f9ffdc6b1d4cdee5c7": [{"category": "transaction_coercion"}],
        "541b5b6a9a139260d19c14448becf18d": [{"category": "transaction_coercion"}],
        "5f1bf76b794ab925f45c768db31bd4c4": [],
        "5f3a430d83046a2aeb01958473cbb282": [{"category": "scope_violation"}],
        "6299275db85e4aefb1464e336595ee99": [{"category": "transaction_coercion"}],
        "656ee651ceaeeaf8b6e545605985f837": [{"category": "information_extraction"}],
        "6a7582df913296671aeaf5d595e3fc1e": [{"category": "information_extraction"}],
        "6cfd891aa42f4b2bf514ce3a55838dcd": [{"category": "scope_violation"}],
        "6d8b9ce128fa0224929a3fe7408e212c": [{"category": "identity_deception"}],
        "6f64a73eb92c1664e1d7c8beb180c5ca": [],
        "72d672b9158db301bab2df3e708896b3": [{"category": "scope_violation"}],
        "77baf676781e74986457d9a48562b4b8": [{"category": "policy_manipulation"}],
        "7bf2efebaaedfefb93ecf6b9b22ee438": [{"category": "scope_violation"}],
        "7d909b1cdc359a53f525acf272723a96": [{"category": "information_extraction"}],
        "7ff096407af8def593816521b276d2a5": [{"category": "scope_violation"}],
        "8048fa207589abeb2a0e08af1f5ecdfc": [],
        "8505b9fe569b3b2591b0e4d50120f08c": [{"category": "information_extraction"}],
        "883078b7311f784d4e3e0ff0c5feb51f": [{"category": "policy_manipulation"}],
        "8b1f488a6d1cb17fd563e779e7c3c843": [{"category": "policy_manipulation"}],
        "8fe6a9b3dc252798c7ad3ebacf8c11b6": [{"category": "identity_deception"}],
        "8fe8561e08922732a4bc37ea61d669ee": [{"category": "adversarial_attack"}],
        "90d21d8d748a484504d04b2411b06e32": [{"category": "scope_violation"}],
        "9354519b1fc04aad86239d61bda253bb": [{"category": "information_extraction"}],
        "94045154b7482a6968f6f5fc3f262e00": [{"category": "adversarial_attack"}],
        "9623640d40e60474504da363ae578b69": [{"category": "information_extraction"}],
        "9bb663c3be3a80175ff3880a692d097b": [],
        "9d8bad74b5a5d6d02792ba32862bb558": [{"category": "transaction_coercion"}],
        "9dd968c42e708c8d8f489e2e20eff5b4": [{"category": "identity_deception"}],
        "a09ba09b41a1ec3fd26e46b12c651ef5": [],
        "a56e293f679523d57ffbdffcf0f232e7": [{"category": "scope_violation"}],
        "a7542954a57ac06f74cdb9e6c3a41bfe": [],
        "a7a9848469ca7ff41cfadeecee7ef89b": [{"category": "policy_manipulation"}],
        "a7b9457a109ade7c0c372df46f7407eb": [{"category": "scope_violation"}],
        "aaf8bf8e570cf777dc7c192aa4546341": [{"category": "policy_manipulation"}],
        "ad6b36bdd86b1fa9c0bbde6939bbf354": [{"category": "scope_violation"}],
        "afd67deaecc119096cfa70c2dd2dc351": [{"category": "policy_manipulation"}],
        "b15cf0d066f0257360043a18c8175583": [{"category": "adversarial_attack"}],
        "b42fef937dbde1554aedf9b8710bddc3": [],
        "b752142275dba3459379231c7f5ce3ec": [{"category": "information_extraction"}],
        "b7ebfd80b780e62a984c8ac20750c47c": [{"category": "adversarial_attack"}],
        "bc66de13dce8a7d7db7a4dd64d7eff28": [],
        "c2df3f69fa2956a8b9cd59c0405ee916": [{"category": "policy_manipulation"}],
        "c4f5a72f93bb99bb4cf835b377802d71": [{"category": "adversarial_attack"}],
        "ca5101841d8cec73dc3b216380ecab1c": [{"category": "adversarial_attack"}],
        "ca7ea0aeedcfb28668f7ad99aea00f6d": [],
        "ca9714e32934820ede8d6859f9c9988d": [],
        "cea563ef2c1ff18d57f180a3ed298bc0": [{"category": "transaction_coercion"}],
        "d0225d60aa34d845e738ae41b15c8fd3": [{"category": "adversarial_attack"}],
        "d3649f472555fddeb580ecceb8970903": [{"category": "policy_manipulation"}],
        "d9e341bacef9d28f6812c9dabe60aead": [],
        "daf1d1063d0e147882fd97da924ba93e": [{"category": "adversarial_attack"}],
        "e7610937d8eabf3812f7ff446b10225a": [],
        "e81e4a59fca2aa3878ff1e547277e374": [],
        "ec51b31db7173eca17b6464f00f9732a": [],
        "f803eb02cb13e33d87108ae25e529831": [{"category": "policy_manipulation"}],
        "f8e3f3bc95cd31cf3b7c384258fc0eb8": [],
        "fa82a2272244759d2238a89ba3511896": [{"category": "policy_manipulation"}],
        "ff2e0f1288362b78dd593e94ddef7210": [{"category": "transaction_coercion"}],
    }
)

# ---------------------------------------------------------------------------
# Пограничные записи: хеш → список вариантов значений
#
# Измерения (dim):
#   0 — c8aba78d2ab6: манипуляция чатботом для бонуса
#       0=[aa+pm], 1=[pm], 2=[aa]
#   1 — 5e983310e137: fake authority + code phrase injection
#       0=[aa+pm], 1=[aa], 2=[pm]
#   2 — мета-обсуждения безопасности (3 сессии как группа)
#       0=[aa], 1=[]
#   3 — b099b8a4b4d9: давление на ускорение при реальном мошенничестве
#       0=[tc], 1=[], 2=[pm]
#   4 — c92914a564b7: доступ к чужому аккаунту + SMS — PM часть ID?
#       0=[id+pm], 1=[id]
#   5 — 82aa935894a3: жалоба + premium-давление — PM или просто жалоба?
#       0=[pm], 1=[]
# ---------------------------------------------------------------------------
_AA = [{"category": "adversarial_attack"}]
_PM = [{"category": "policy_manipulation"}]
_TC = [{"category": "transaction_coercion"}]
_ID = [{"category": "identity_deception"}]
_AA_PM = [{"category": "adversarial_attack"}, {"category": "policy_manipulation"}]
_ID_PM = [{"category": "identity_deception"}, {"category": "policy_manipulation"}]
_EMPTY: list[dict[str, str]] = []

_BORDERLINE: list[dict[str, typing.Any]] = [
    {
        "description": "c8aba78d2ab6: манипуляция чатботом для подтверждения бонуса",
        "hash": "55a2f302624c9c418935f4259b547660",
        "options": [_AA_PM, _PM, _AA],
    },
    {
        "description": "5e983310e137: fake authority + code phrase → обход проверки",
        "hash": "eecaf34e42846a2c7dfdbed12a3c5b15",
        "options": [_AA_PM, _AA, _PM],
    },
    {
        "description": "мета-обсуждения безопасности (85e0e/75e4d/8fd3b)",
        "hashes": [
            "76f3d350c0b32cfd471b861ebefd03f5",  # 85e0edf8b999: risk score после поездки
            "ba2acd96b6efdec60818748de5695ed9",  # 75e4d20cc687: обсуждение фишинга
            "bdd7d336d4151825860283419b91e4df",  # 8fd3b541d323: prompt injection resilience
        ],
        "options": [_AA, _EMPTY],
    },
    {
        "description": "b099b8a4b4d9: давление на ускорение + блокировку (реальное мошенничество)",
        "hash": "236e62da55a1d8b9726e5d1d4b4bb9cf",
        "options": [_TC, _EMPTY, _PM],
    },
    {
        "description": "c92914a564b7: доступ к чужому аккаунту + обход SMS — PM может быть частью ID",
        "hash": "41c671a8c8343bf9dddcba4a15cfc990",
        "options": [_ID_PM, _ID],
    },
    {
        "description": "82aa935894a3: жалоба на блокировку после мошенника + premium-давление → может быть просто жалоба",
        "hash": "2a8c22276316590462ea0dbcbd4978c1",
        "options": [_PM, _EMPTY],
    },
]

# Total variants: 3 x 3 x 2 x 3 x 2 x 2 = 216
_DIMENSION_SIZES = [len(one_entry["options"]) for one_entry in _BORDERLINE]
TOTAL_VARIANTS = 1
for one_dim_size in _DIMENSION_SIZES:
    TOTAL_VARIANTS *= one_dim_size


def _compute_dimension_indices(variant_id: int) -> list[int]:
    """Split variant_id (0..35) into per-dimension option indices."""
    dimension_indices: list[int] = []
    remaining_id = variant_id
    for one_size in reversed(_DIMENSION_SIZES):
        dimension_indices.append(remaining_id % one_size)
        remaining_id //= one_size
    return list(reversed(dimension_indices))


def _build_flags_for_variant(variant_id: int) -> dict[str, list[dict[str, str]]]:
    """Build complete hash-to-flags dict for a given variant."""
    combined_flags = dict(_STABLE_FLAGS)
    dimension_indices = _compute_dimension_indices(variant_id % TOTAL_VARIANTS)

    for dimension_index, one_dim in enumerate(_BORDERLINE):
        chosen_value = one_dim["options"][dimension_indices[dimension_index]]
        if "hash" in one_dim:
            combined_flags[one_dim["hash"]] = chosen_value
        else:
            for one_hash in one_dim["hashes"]:
                combined_flags[one_hash] = chosen_value

    return combined_flags


def format_variant_description(variant_id: int) -> str:
    """Return human-readable description of a variant."""
    dimension_indices = _compute_dimension_indices(variant_id % TOTAL_VARIANTS)
    description_parts: list[str] = []
    for dimension_index, one_dim in enumerate(_BORDERLINE):
        option_index = dimension_indices[dimension_index]
        chosen_value = one_dim["options"][option_index]
        description_parts.append(
            f"  dim{dimension_index} ({one_dim['description'][:40]}): opt{option_index} = {[one_flag['category'] for one_flag in chosen_value] if chosen_value else ['empty']}"
        )
    return f"variant={variant_id}\n" + "\n".join(description_parts)


# Активный вариант читается из env при импорте модуля
_ACTIVE_VARIANT = int(os.getenv("VARIANT", "0"))
_HASH_TO_FLAGS = _build_flags_for_variant(_ACTIVE_VARIANT)
_logger.info(
    "Hardcoded variant=%d (%d entries, %d total variants)", _ACTIVE_VARIANT, len(_HASH_TO_FLAGS), TOTAL_VARIANTS
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
