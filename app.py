"""Interactive QChat simulation for cryptographic workflows.

This Streamlit application demonstrates core cryptographic primitives that a
group messaging system might rely on. The page is split into interactive
sections that cover:

* Post-quantum key generation using Dilithium.
* Message signing and verification with the generated key material.
* Authenticated encryption and decryption with AES-GCM.
* TreeKEM-inspired group key updates that react to membership changes.

The goal is to make the impact of each operation visible so that users can see
how cryptographic state evolves as actions are performed.
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple

import dilithium
import networkx as nx
import plotly.graph_objects as go
import streamlit as st
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class DilithiumKeyPair:
    """Container for a Dilithium key pair."""

    private_key: dilithium.PrivateKey
    public_key: dilithium.PublicKey


@dataclass
class AESEncryptionResult:
    """Outcome of an AES-GCM encryption operation."""

    key: bytes
    nonce: bytes
    ciphertext: bytes
    tag: bytes


# ---------------------------------------------------------------------------
# Cryptographic helpers
# ---------------------------------------------------------------------------


def generate_dilithium_keypair() -> DilithiumKeyPair:
    """Create a fresh Dilithium key pair for signing and verification."""

    private_key = dilithium.PrivateKey.generate()
    public_key = private_key.public_key()
    return DilithiumKeyPair(private_key=private_key, public_key=public_key)


def sign_message(key_pair: DilithiumKeyPair, message: bytes) -> bytes:
    """Produce a Dilithium signature for ``message``."""

    return key_pair.private_key.sign(message)


def verify_signature(public_key: dilithium.PublicKey, message: bytes, signature: bytes) -> bool:
    """Check whether ``signature`` is valid for ``message``."""

    try:
        public_key.verify(signature, message)
        return True
    except Exception:  # pragma: no cover - library-specific exceptions
        return False


def encrypt_message(plaintext: bytes, key: bytes | None = None) -> AESEncryptionResult:
    """Encrypt ``plaintext`` with AES-GCM, returning the full result."""

    if key is None:
        key = secrets.token_bytes(32)  # AES-256 key material

    nonce = secrets.token_bytes(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return AESEncryptionResult(key=key, nonce=nonce, ciphertext=ciphertext, tag=encryptor.tag)


def decrypt_message(result: AESEncryptionResult) -> bytes:
    """Decrypt an :class:`AESEncryptionResult` back into plaintext."""

    decryptor = Cipher(algorithms.AES(result.key), modes.GCM(result.nonce, result.tag)).decryptor()
    return decryptor.update(result.ciphertext) + decryptor.finalize()


# ---------------------------------------------------------------------------
# TreeKEM simulation helpers
# ---------------------------------------------------------------------------


def hkdf_derive(salt: bytes, info: bytes, length: int = 32) -> bytes:
    """Derive deterministic key material using HKDF."""

    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hkdf.derive(b"QCHAT_TREEKEM")


def simulate_treekem(group_name: str, members: Iterable[str]) -> Tuple[bytes, Dict[str, bytes]]:
    """Generate root and member keys for a simplified TreeKEM demo."""

    member_list = sorted(set(member.strip() for member in members if member.strip()))

    # The root key is anchored in the group name and current membership.
    member_digest = b"|".join(member.encode("utf-8") for member in member_list) or b"no-members"
    root_key = hkdf_derive(salt=group_name.encode("utf-8"), info=member_digest)

    member_keys: Dict[str, bytes] = {}
    for member in member_list:
        info = f"leaf::{member}".encode("utf-8")
        member_keys[member] = hkdf_derive(salt=root_key, info=info)

    return root_key, member_keys


def plot_treekem(members: List[str], root_key: bytes, member_keys: Dict[str, bytes]) -> go.Figure:
    """Create a Plotly figure representing the TreeKEM group state."""

    graph = nx.Graph()
    graph.add_node("Root")

    for member in members:
        graph.add_node(member)
        graph.add_edge("Root", member)

    if not members:
        positions = {"Root": (0.0, 0.0)}
    else:
        positions = nx.spring_layout(graph, seed=42)

    edge_x: List[float] = []
    edge_y: List[float] = []
    for edge in graph.edges():
        x0, y0 = positions[edge[0]]
        x1, y1 = positions[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line=dict(width=1, color="#888"),
        hoverinfo="none",
        mode="lines",
    )

    node_x: List[float] = []
    node_y: List[float] = []
    labels: List[str] = []
    colors: List[str] = []

    root_label = _format_key_snippet("Root key", root_key)
    node_x.append(positions["Root"][0])
    node_y.append(positions["Root"][1])
    labels.append(root_label)
    colors.append("#1f77b4")

    for member in members:
        node_x.append(positions[member][0])
        node_y.append(positions[member][1])
        member_key = member_keys.get(member)
        labels.append(_format_key_snippet(member, member_key))
        colors.append("#ff7f0e")

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers",
        marker=dict(showscale=False, color=colors, size=28, line=dict(width=2, color="#FFFFFF")),
        text=labels,
        hoverinfo="text",
    )

    return go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title="TreeKEM Group Structure",
            titlefont_size=18,
            title_x=0.5,
            showlegend=False,
            hovermode="closest",
            margin=dict(l=20, r=20, t=60, b=20),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        ),
    )


def _format_key_snippet(title: str, key_material: bytes | None) -> str:
    """Render a short label with base64-encoded key material."""

    if not key_material:
        return f"{title}\n(no key)"

    snippet = base64.b64encode(key_material).decode("utf-8")[:24]
    return f"{title}\n{snippet}…"


# ---------------------------------------------------------------------------
# Streamlit state initialisation
# ---------------------------------------------------------------------------


def init_state() -> None:
    """Ensure all Streamlit session state entries are populated."""

    if "group_name" not in st.session_state:
        st.session_state.group_name = "birds"

    if "members" not in st.session_state:
        st.session_state.members: List[str] = ["Alice", "Bob", "Charlie"]

    if "history" not in st.session_state:
        st.session_state.history: List[str] = []

    if "dilithium_keys" not in st.session_state:
        st.session_state.dilithium_keys: DilithiumKeyPair | None = None

    if "latest_signature" not in st.session_state:
        st.session_state.latest_signature: bytes | None = None

    if "latest_signed_message" not in st.session_state:
        st.session_state.latest_signed_message: str | None = None

    if "aes_result" not in st.session_state:
        st.session_state.aes_result: AESEncryptionResult | None = None

    if "treekem_state" not in st.session_state:
        root_key, member_keys = simulate_treekem(st.session_state.group_name, st.session_state.members)
        st.session_state.treekem_state = dict(root_key=root_key, member_keys=member_keys)


def update_treekem_state() -> None:
    """Recompute TreeKEM state and log the change."""

    root_key, member_keys = simulate_treekem(st.session_state.group_name, st.session_state.members)
    st.session_state.treekem_state = dict(root_key=root_key, member_keys=member_keys)


# ---------------------------------------------------------------------------
# Streamlit UI helpers
# ---------------------------------------------------------------------------


def render_sidebar() -> None:
    """Render the sidebar with high-level group controls."""

    with st.sidebar:
        st.header("Group configuration")
        group_name_input = st.text_input("Group name", value=st.session_state.group_name)

        if group_name_input != st.session_state.group_name:
            st.session_state.group_name = group_name_input
            update_treekem_state()
            st.session_state.history.append(f"Group renamed to '{group_name_input}'.")

        st.markdown("### Current members")
        if st.session_state.members:
            for member in st.session_state.members:
                st.markdown(f"- {member}")
        else:
            st.info("No members in the group. Add one from the main panel.")

        root_key = st.session_state.treekem_state["root_key"]
        st.markdown("### Root secret")
        st.code(base64.b64encode(root_key).decode("utf-8"))


def render_key_generation_tab() -> None:
    """Display the key generation and signing workflow."""

    st.subheader("Dilithium key generation & signing")
    st.write(
        "Generate a post-quantum key pair, sign a message, and verify the "
        "signature to understand how authenticity is maintained."
    )

    if st.button("Generate new Dilithium keys", key="generate_keys"):
        st.session_state.dilithium_keys = generate_dilithium_keypair()
        st.session_state.history.append("Generated a fresh Dilithium key pair.")
        st.session_state.latest_signature = None
        st.session_state.latest_signed_message = None
        st.session_state.verify_message = ""

    key_pair = st.session_state.dilithium_keys
    if key_pair is None:
        st.warning("Generate a key pair to continue.")
        return

    public_key_bytes = key_pair.public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    st.markdown("#### Public key")
    st.code(base64.b64encode(public_key_bytes).decode("utf-8"))

    message = st.text_area(
        "Message to sign",
        value=st.session_state.latest_signed_message or "Hello secure world!",
    )

    if st.button("Sign message", key="sign_message"):
        signature = sign_message(key_pair, message.encode("utf-8"))
        st.session_state.latest_signature = signature
        st.session_state.latest_signed_message = message
        st.session_state.verify_message = message
        st.session_state.history.append("Signed a message with the Dilithium private key.")

    signature = st.session_state.latest_signature
    if signature:
        st.markdown("#### Latest signature")
        st.code(base64.b64encode(signature).decode("utf-8"))

        verify_message = st.text_area(
            "Message to verify",
            value=st.session_state.latest_signed_message or "",
            key="verify_message",
        )

        if st.button("Verify signature", key="verify_signature"):
            valid = verify_signature(
                st.session_state.dilithium_keys.public_key,
                verify_message.encode("utf-8"),
                signature,
            )
            if valid:
                st.success("Signature verified successfully.")
                st.session_state.history.append("Verified the Dilithium signature successfully.")
            else:
                st.error("Signature verification failed. Try changing the message text.")
                st.session_state.history.append("Attempted to verify the signature but it failed.")
    else:
        st.info("Sign a message to produce a signature that can be verified.")


def render_encryption_tab() -> None:
    """Display the encryption and decryption workflow."""

    st.subheader("AES-GCM message encryption")
    st.write(
        "This section encrypts the supplied message with authenticated "
        "encryption (AES-GCM). Observe how the nonce, ciphertext, and tag "
        "change for every encryption operation."
    )

    plaintext = st.text_area("Plaintext message", value="TreeKEM keeps our group chats private.")

    col_encrypt, col_decrypt = st.columns(2)

    if col_encrypt.button("Encrypt message"):
        result = encrypt_message(plaintext.encode("utf-8"))
        st.session_state.aes_result = result
        st.session_state.history.append("Encrypted a message with AES-GCM.")

    aes_result = st.session_state.aes_result
    if aes_result:
        st.markdown("#### Ciphertext artefacts")
        st.code(jsonify_encryption_result(aes_result))

        if col_decrypt.button("Decrypt last ciphertext"):
            try:
                recovered = decrypt_message(aes_result).decode("utf-8")
            except Exception:  # pragma: no cover - cryptography exceptions vary
                st.error("Decryption failed. The key, nonce, or tag may be corrupted.")
                st.session_state.history.append("Failed to decrypt the AES-GCM ciphertext.")
            else:
                st.success(f"Recovered plaintext: {recovered}")
                st.session_state.history.append("Decrypted the AES-GCM ciphertext.")
    else:
        st.info("Encrypt a message to view the resulting ciphertext and metadata.")


def jsonify_encryption_result(result: AESEncryptionResult) -> str:
    """Render AES-GCM components as a JSON-style string."""

    payload = {
        "key": base64.b64encode(result.key).decode("utf-8"),
        "nonce": base64.b64encode(result.nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(result.ciphertext).decode("utf-8"),
        "tag": base64.b64encode(result.tag).decode("utf-8"),
    }
    lines = ["{"]
    for idx, (field, value) in enumerate(payload.items()):
        comma = "," if idx < len(payload) - 1 else ""
        lines.append(f"  \"{field}\": \"{value}\"{comma}")
    lines.append("}")
    return "\n".join(lines)


def render_group_tab() -> None:
    """Display TreeKEM membership management and visualisation."""

    st.subheader("TreeKEM group dynamics")
    st.write(
        "Add or remove members to watch the simulated TreeKEM root key and leaf "
        "keys update instantly. The visualisation highlights the current "
        "structure of the group key tree."
    )

    add_col, remove_col = st.columns(2)

    with add_col:
        new_member = st.text_input("Member to add", key="add_member")
        if st.button("Add member"):
            member = new_member.strip()
            if not member:
                st.warning("Provide a member name before adding.")
            elif member in st.session_state.members:
                st.info(f"{member} is already part of the group.")
            else:
                st.session_state.members.append(member)
                update_treekem_state()
                st.session_state.history.append(f"Added member '{member}'.")
                st.session_state.add_member = ""

    with remove_col:
        removable_members = st.session_state.members or ["(no members)"]
        to_remove = st.selectbox("Member to remove", options=removable_members, key="remove_member")
        if st.button("Remove member") and st.session_state.members:
            st.session_state.members = [m for m in st.session_state.members if m != to_remove]
            update_treekem_state()
            st.session_state.history.append(f"Removed member '{to_remove}'.")

    treekem_state = st.session_state.treekem_state
    members = st.session_state.members

    st.markdown("#### Current TreeKEM keys")
    col_root, col_members = st.columns([1, 2])
    with col_root:
        st.caption("Root key")
        st.code(base64.b64encode(treekem_state["root_key"]).decode("utf-8"))

    with col_members:
        if members:
            for member in members:
                leaf_key = treekem_state["member_keys"].get(member)
                st.write(f"**{member}** — {base64.b64encode(leaf_key).decode('utf-8')}")
        else:
            st.info("No members to display. Add someone to populate the tree.")

    figure = plot_treekem(members, treekem_state["root_key"], treekem_state["member_keys"])
    st.plotly_chart(figure, use_container_width=True)


def render_history() -> None:
    """Display a chronological log of user actions."""

    st.markdown("### Activity log")
    if not st.session_state.history:
        st.info("Perform an action above to populate the log.")
        return

    for entry in reversed(st.session_state.history[-15:]):
        st.write(f"- {entry}")


# ---------------------------------------------------------------------------
# Streamlit page layout
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point for the Streamlit application."""

    st.set_page_config(page_title="QChat Cryptography Showcase", layout="wide")
    init_state()
    render_sidebar()

    st.title("QChat cryptographic operations")
    st.write(
        "Interact with each panel to see how keys, signatures, and encrypted "
        "messages evolve. The widgets are connected so that you can explore "
        "the impact of every operation on the system's state."
    )

    tab_keys, tab_encryption, tab_group = st.tabs([
        "Key generation & signing",
        "Message encryption",
        "TreeKEM group management",
    ])

    with tab_keys:
        render_key_generation_tab()

    with tab_encryption:
        render_encryption_tab()

    with tab_group:
        render_group_tab()

    render_history()


if __name__ == "__main__":
    main()

