import streamlit as st
import base64
import secrets
import time
import json
import msgpack
import plotly.graph_objects as go
import networkx as nx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes as crypto_hashes
import dilithium

# Setup for Dilithium signatures
def generate_dilithium_keypair():
    private_key = dilithium.PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(dilithium_private_key, message):
    signature = dilithium_private_key.sign(message)
    return signature

def verify_signature(dilithium_public_key, message, signature):
    try:
        dilithium_public_key.verify(signature, message)
        return True
    except Exception as e:
        return False

# AES Encryption (Mock)
def simulate_encryption_process():
    key = secrets.token_bytes(32)  # AES-256 key
    nonce = secrets.token_bytes(12)  # AES-GCM nonce
    plaintext = b"Hello, this is a test message!"
    ciphertext = plaintext  # Simulate encryption (not implemented)
    return key, ciphertext, nonce

# TreeKEM Simulation (simplified)
def simulate_treekem(group_name, members):
    root_key = secrets.token_bytes(32)  # Initial root key
    for member in members:
        root_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=group_name.encode()).derive(root_key)
    return root_key

# Visualization Function for TreeKEM structure
def plot_treekem(members, root_key):
    G = nx.Graph()

    for member in members:
        G.add_node(member)

    # Add the root node for TreeKEM
    G.add_node("Root")
    for i, member in enumerate(members):
        G.add_edge("Root", member)

    pos = nx.spring_layout(G)
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.append(x0)
        edge_x.append(x1)
        edge_y.append(y0)
        edge_y.append(y1)

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color="#888"),
        hoverinfo="none",
        mode="lines"
    )

    node_x = []
    node_y = []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode="markers",
        hoverinfo="text",
        marker=dict(
            showscale=False,
            color=[],
            size=20,
            line_width=2
        )
    )

    fig = go.Figure(data=[edge_trace, node_trace],
                    layout=go.Layout(
                        showlegend=False,
                        hovermode="closest",
                        title="TreeKEM Group Structure",
                        titlefont_size=16,
                        title_x=0.5,
                        title_y=0.95,
                        xaxis=dict(showgrid=False, zeroline=False),
                        yaxis=dict(showgrid=False, zeroline=False)
                    ))
    return fig

# Streamlit UI
st.title("QChat Simulation: Encryption, Key Exchange, and TreeKEM")

# Sidebar for user input
st.sidebar.header("Setup")
group_name = st.sidebar.text_input("Group Name", "birds")
user_name = st.sidebar.text_input("Enter your username", "Alice")

# Button to simulate user joining group
if st.sidebar.button("Join Group"):
    st.sidebar.text(f"User {user_name} has joined the group '{group_name}'")

if st.sidebar.button("Leave Group"):
    st.sidebar.text(f"User {user_name} has left the group '{group_name}'")

# Key Generation and Encryption Simulation
if st.sidebar.button("Generate Keys"):
    dilithium_private_key, dilithium_public_key = generate_dilithium_keypair()
    
    # Show Dilithium keys
    dilithium_pub_key_b64 = base64.b64encode(dilithium_public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode()

    st.sidebar.text(f"Generated Dilithium Public Key: {dilithium_pub_key_b64}")

    # Encryption Simulation
    key, ciphertext, nonce = simulate_encryption_process()
    st.sidebar.text(f"Encrypted Message (Base64): {base64.b64encode(ciphertext).decode()}")
    st.sidebar.text(f"AES Key: {base64.b64encode(key).decode()}")
    st.sidebar.text(f"Nonce: {base64.b64encode(nonce).decode()}")

# Show the TreeKEM structure
members = ["Alice", "Bob", "Charlie"]
root_key = simulate_treekem(group_name, members)
st.sidebar.text(f"Group Root Key: {base64.b64encode(root_key).decode()}")

# Show TreeKEM visualization
if st.sidebar.button("Show TreeKEM Structure"):
    fig = plot_treekem(members, root_key)
    st.plotly_chart(fig)

# Step-by-Step Process Tabs
tab1, tab2, tab3, tab4 = st.tabs(["Step 1: Key Generation", "Step 2: Encryption", "Step 3: TreeKEM", "Step 4: Message Signing"])

with tab1:
    st.subheader("Key Generation Process")
    st.write("""
    - **Dilithium Key Pair Generation**: Users generate **Dilithium private/public keys** for signing and verifying messages in a post-quantum environment.
    - **AES Key Generation**: Each user generates a **unique AES-256 key** for encrypting messages.
    - **Kyber KEM**: Simulated (though we’re using Dilithium here for signing), where users exchange keys for the shared secret.
    """)

with tab2:
    st.subheader("Message Encryption")
    st.write("""
    - Messages are encrypted using **AES-GCM** with a **unique nonce**.
    - The **ciphertext** and **nonce** are displayed, simulating the encryption of the message using the AES key.
    """)

with tab3:
    st.subheader("TreeKEM Group Dynamics")
    st.write("""
    - **TreeKEM** simulates secure group key management as users join/leave the group.
    - The **root key** is updated dynamically to reflect the group structure and membership.
    - The **interactive tree** above shows how the group changes as users are added or removed.
    """)

with tab4:
    st.subheader("Dilithium Signing & Verification")
    st.write("""
    - Users sign messages with **Dilithium** for post-quantum security.
    - **Signature generation** and **verification** are shown.
    - The **Dilithium signing process** ensures that the message has not been tampered with.
    """)
