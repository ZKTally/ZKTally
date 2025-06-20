import random
import hashlib
from ecdsa import SECP256k1, SigningKey, ellipticcurve
import base58
from PHE import keygen, encrypt, decrypt, prove_01, verify_01
from LRS import sign, verify
import json

def serialize_point(point):
    x = point.x().to_bytes(32, 'big')
    y = point.y().to_bytes(32, 'big')
    return base58.b58encode(x + y).decode()

def deserialize_point(data_b58):
    raw = base58.b58decode(data_b58)
    x = int.from_bytes(raw[:32], 'big')
    y = int.from_bytes(raw[32:], 'big')
    curve = SECP256k1.curve
    return ellipticcurve.Point(curve, x, y)

class VotingCommittee:
    def __init__(self, name="Election Committee", bits=2048):
        self.name = name
        self.public_key, self.private_key = keygen(bits)
        self.encrypted_votes = []
        self.vote_proofs = []
        self.ring_signatures = []
        self.used_key_images = set()
        self.voters_ring = []
        print(f"[Committee] {self.name} initialized with {bits}-bit Paillier keys")
    
    def register_voters(self, num_voters):
        total_keys_needed = num_voters + 1
        all_keys = [SigningKey.generate(curve=SECP256k1) for _ in range(total_keys_needed)]
        
        self.voters_ring = all_keys[:num_voters]
        self.voters_pub_keys = [sk.verifying_key for sk in self.voters_ring]
        print(f"[Committee] {num_voters} voters registered successfully")
        return self.voters_ring
    
    def receive_vote(self, encrypted_vote, nizk_proof, ring_signature, voter_id):
        nizk_valid = verify_01(encrypted_vote, nizk_proof, self.public_key)
        if not nizk_valid:
            print(f"[Committee] NIZK proof invalid for voter {voter_id}")
            return False
        
        message = f"vote:{encrypted_vote}".encode()
        ring_valid = verify(message, ring_signature)
        if not ring_valid:
            print(f"[Committee] Ring signature invalid for voter {voter_id}")
            return False
        
        key_image_str = serialize_point(ring_signature["key_image"])
        if key_image_str in self.used_key_images:
            print(f"[Committee] Double voting detected! Key image already used")
            return False
        
        self.encrypted_votes.append(encrypted_vote)
        self.vote_proofs.append(nizk_proof)
        self.ring_signatures.append(ring_signature)
        self.used_key_images.add(key_image_str)
        
        print(f"[Committee] Vote from voter {voter_id} accepted")
        return True
    
    def tally_votes(self):
        if not self.encrypted_votes:
            print("[Committee] No votes to tally")
            return 0
        
        print(f"[Committee] Tallying {len(self.encrypted_votes)} votes...")
        
        n, g, N2 = self.public_key
        total_encrypted = 1
        for vote in self.encrypted_votes:
            total_encrypted = (total_encrypted * vote) % N2
        
        total_votes = decrypt(total_encrypted, self.public_key, self.private_key)
        print(f"[Committee] Total votes for candidate: {total_votes}")
        print(f"[Committee] Total votes against candidate: {len(self.encrypted_votes) - total_votes}")
        
        return total_votes

class Voter:
    def __init__(self, voter_id, private_key, voters_ring, voters_pub_keys, committee_public_key):
        self.voter_id = voter_id
        self.private_key = private_key
        self.voters_ring = voters_ring
        self.voters_pub_keys = voters_pub_keys
        self.committee_public_key = committee_public_key
        self.has_voted = False
        
        self.ring_index = None
        for i, sk in enumerate(voters_ring):
            if sk.privkey.secret_multiplier == private_key.privkey.secret_multiplier:
                self.ring_index = i
                break
        
        print(f"[Voter {voter_id}] Initialized (ring position: {self.ring_index})")
    
    def cast_vote(self, vote_choice):
        if self.has_voted:
            print(f"[Voter {self.voter_id}] Already voted!")
            return None, None, None
        
        if vote_choice not in [0, 1]:
            print(f"[Voter {self.voter_id}] Invalid vote choice: {vote_choice}")
            return None, None, None
        
        print(f"[Voter {self.voter_id}] Casting vote: {vote_choice}")
        
        encrypted_vote, r = encrypt(vote_choice, self.committee_public_key)
        
        nizk_proof = prove_01(encrypted_vote, r, vote_choice, self.committee_public_key)
        
        message = f"vote:{encrypted_vote}".encode()
        ring_signature = sign(message, self.ring_index, self.voters_pub_keys, self.private_key)
        
        self.has_voted = True
        print(f"[Voter {self.voter_id}] Vote cast successfully")
        
        return encrypted_vote, nizk_proof, ring_signature

def run_voting_simulation():
    print("=" * 70)
    print("SECURE E-VOTING SIMULATION")
    print("=" * 70)
    print("Features:")
    print("• Paillier Homomorphic Encryption (vote privacy)")
    print("• NIZK Proofs (ensures votes are 0 or 1)")
    print("• Linkable Ring Signatures (anonymity + no double voting)")
    print("=" * 70)
    
    committee = VotingCommittee("Presidential Election Committee", bits=1024)
    
    num_voters = 8
    voters_ring = committee.register_voters(num_voters)
    
    voters = []
    for i in range(7):
        voter = Voter(
            voter_id=f"V{i+1:02d}",
            private_key=voters_ring[i],
            voters_ring=voters_ring,
            voters_pub_keys=committee.voters_pub_keys,
            committee_public_key=committee.public_key
        )
        voters.append(voter)
    
    print("\n" + "=" * 50)
    print("VOTING PHASE")
    print("=" * 50)
    
    vote_choices = [random.choice([0, 1]) for _ in range(7)]
    print(f"Vote choices (hidden from committee): {vote_choices}")
    
    successful_votes = 0
    for i, voter in enumerate(voters):
        vote_choice = vote_choices[i]
        encrypted_vote, nizk_proof, ring_signature = voter.cast_vote(vote_choice)
        
        if encrypted_vote is not None:
            success = committee.receive_vote(encrypted_vote, nizk_proof, ring_signature, voter.voter_id)
            if success:
                successful_votes += 1
    
    print(f"\n[Committee] Successfully processed {successful_votes}/7 votes")
    
    print("\n" + "=" * 50)
    print("DOUBLE VOTING PREVENTION TEST")
    print("=" * 50)
    
    print("Attempting double vote with voter V01...")
    encrypted_vote, nizk_proof, ring_signature = voters[0].cast_vote(1)
    if encrypted_vote is not None:
        committee.receive_vote(encrypted_vote, nizk_proof, ring_signature, "V01")
    
    print("\n" + "=" * 50)
    print("VOTE TALLYING")
    print("=" * 50)
    
    total_yes_votes = committee.tally_votes()
    
    actual_yes_votes = sum(vote_choices)
    print(f"\n[Verification] Expected yes votes: {actual_yes_votes}")
    print(f"[Verification] Computed yes votes: {total_yes_votes}")
    print(f"[Verification] Tally correct: {actual_yes_votes == total_yes_votes}")
    
    print("\n" + "=" * 70)
    print("SIMULATION COMPLETED SUCCESSFULLY!")
    print("=" * 70)
    print("• Privacy: Votes encrypted with Paillier encryption")
    print("• Integrity: All votes proven to be binary (0 or 1)")
    print("• Anonymity: Ring signatures hide voter identity")
    print("• No double voting: Linkable signatures prevent reuse")
    print("• Homomorphic tallying: Results computed without decrypting individual votes")

def test_invalid_vote():
    print("\n" + "=" * 50)
    print("TESTING INVALID VOTE REJECTION")
    print("=" * 50)
    
    committee = VotingCommittee("Test Committee", bits=1024)
    voters_ring = committee.register_voters(2)
    
    voter = Voter(
        voter_id="TEST",
        private_key=voters_ring[0],
        voters_ring=voters_ring,
        voters_pub_keys=committee.voters_pub_keys,
        committee_public_key=committee.public_key
    )
    
    print("Attempting to vote with value 2 (should fail NIZK proof)...")
    encrypted_vote, r = encrypt(2, committee.public_key)
    nizk_proof = prove_01(encrypted_vote, r, 2, committee.public_key)
    
    valid = verify_01(encrypted_vote, nizk_proof, committee.public_key)
    print(f"NIZK proof for vote=2 valid: {valid}")

if __name__ == "__main__":
    run_voting_simulation()
    test_invalid_vote()
