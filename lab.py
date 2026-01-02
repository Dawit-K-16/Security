# ================= AES-128 IMPLEMENTATION ===================

# ---------------- S-BOX ----------------
S_BOX = [
[99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118],   
[202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192], 
[183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21],     
[4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117],         
[9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132],          
[83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207],         
[208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168],        
[81,163,64,143,146,157,56,245,188,182,218,33,16,255,243,210],     
[205,12,19,236,95,151,68,23,196,167,126,61,100,93,25,115],        
[96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219],        
[224,50,58,10,73,6,36,92,194,211,172,98,145,149,228,121],         
[231,200,55,109,141,213,78,169,108,86,244,234,101,122,174,8],     
[186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138],     
[112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158],         
[225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223],    
[140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22]        
]  # S-Box for SubBytes step, used for confusion in AES

# ---------------- RCON ----------------
RCON = [
[1,0,0,0],[2,0,0,0],[4,0,0,0],[8,0,0,0],      # Round constants for key expansion
[16,0,0,0],[32,0,0,0],[64,0,0,0],[128,0,0,0],
[27,0,0,0],[54,0,0,0]
]

# ---------------- HELPERS ----------------
def print_state(state, title):
    print(f"\n--- {title} ---")                     # Print a header
    for row in state:                               # Print each row of state matrix
        print(" ".join(f"{b:02X}" for b in row))   # Show byte in 2-digit hex

def xor_words(a, b):
    return [x ^ y for x, y in zip(a, b)]           # XOR two 4-byte words element-wise

def rot_word(w):
    return w[1:] + w[:1]                           # Rotate a 4-byte word left by 1 byte

def sub_word(w):
    return [S_BOX[b >> 4][b & 0x0F] for b in w]   # Substitute each byte using S-Box

# ---------------- KEY EXPANSION ----------------
def key_expansion(key):
    key = key[:16].ljust(16)                       # Pad or truncate key to 16 bytes
    key_bytes = [ord(c) for c in key]              # Convert key to byte values
    w = [key_bytes[i:i+4] for i in range(0, 16, 4)] # Initial 4 words of key

    for i in range(4, 44):                         # Generate remaining 40 words
        temp = w[i-1]                              
        if i % 4 == 0:                             # Every 4th word
            temp = xor_words(sub_word(rot_word(temp)), RCON[i//4 - 1])  # Apply RotWord, SubWord, RCON
        w.append(xor_words(w[i-4], temp))          # XOR with word 4 positions back
    return w                                        # Return 44-word expanded key

# ---------------- ROUND OPS ----------------
def add_round_key(state, rk):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= rk[i][j]               # XOR state with round key

def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            b = state[i][j]
            state[i][j] = S_BOX[b >> 4][b & 0x0F] # Apply S-Box substitution to each byte

def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]        # Row 1 shift left 1
    state[2] = state[2][2:] + state[2][:2]        # Row 2 shift left 2
    state[3] = state[3][3:] + state[3][:3]        # Row 3 shift left 3

def gmul(a, b):
    p = 0
    for _ in range(8):                             # Multiply in GF(2^8)
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

def mix_columns(state):
    for c in range(4):                             # For each column
        col = [state[r][c] for r in range(4)]     # Copy column
        state[0][c] = gmul(col[0],2)^gmul(col[1],3)^col[2]^col[3]
        state[1][c] = col[0]^gmul(col[1],2)^gmul(col[2],3)^col[3]
        state[2][c] = col[0]^col[1]^gmul(col[2],2)^gmul(col[3],3)
        state[3][c] = gmul(col[0],3)^col[1]^col[2]^gmul(col[3],2)

# ---------------- ENCRYPT ----------------
def encrypt(pt, key):
    pt = pt[:16].ljust(16)                         # Pad/truncate plaintext to 16 bytes
    state = [[ord(pt[i + 4*j]) for i in range(4)] for j in range(4)] # Convert to 4x4 state
    keys = key_expansion(key)                      # Expand the key

    print_state(state, "Initial Text State")       # Show initial plaintext
    print_state(keys[0:4], "Initial Key (Round 0 Key)") # Show initial key

    add_round_key(state, keys[0:4])                # Pre-round AddRoundKey
    print_state(state, "Text State After Round 0")

    for r in range(1, 10):                         # Rounds 1 to 9
        sub_bytes(state)                            # Step 1: SubBytes
        shift_rows(state)                           # Step 2: ShiftRows
        mix_columns(state)                          # Step 3: MixColumns
        print_state(keys[4*r:4*(r+1)], f"Round {r} Key") # Show round key
        add_round_key(state, keys[4*r:4*(r+1)])    # Step 4: AddRoundKey
        print_state(state, f"Text State After Round {r}")

    sub_bytes(state)                                # Round 10 SubBytes
    shift_rows(state)                               # Round 10 ShiftRows
    print_state(keys[40:44], "Round 10 Key")       # Show final round key
    add_round_key(state, keys[40:44])              # Round 10 AddRoundKey
    print_state(state, "Final Ciphertext State")   # Show final encrypted state

    return state

# ---------------- MAIN MENU ----------------
def main():
    print("AES-128 Demonstration")
    print("1. Encrypt")                              # Menu option 1
    print("2. Decrypt (not traced)")                # Menu option 2
    choice = input("Select option: ")              # Ask user choice

    text = input("Enter text (16 chars): ")        # Input plaintext
    key = input("Enter key (16 chars): ")          # Input key

    if choice == "1":
        encrypt(text, key)                          # Call encrypt function
    else:
        print("Decryption trace not enabled in this demo.") # Placeholder for decryption

if __name__ == "__main__":
    main()                                          # Run main menu
#Dawit kassa 002
#Yeabkal Abayew 090
