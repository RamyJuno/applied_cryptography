from ecdsa import ECDSA_generate_keys, ECDSA_sign, ECDSA_verify
from ecelgamal import ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt, bruteECLog, ECencode
from rfc7748 import add, mult, computeVcoordinate
import random

# Constants
p = 2**255 - 19
ORDER = 2**252 + 27742317777372353535851937790883648493
BaseU = 9
BaseV = computeVcoordinate(BaseU)
base_point = (BaseU, BaseV)

NUM_VOTERS = 10
NUM_CANDIDATES = 5

# Step 1: Voter Key Generation
def generate_voter_keys(num_voters):
    voter_keys = {}
    for voter_id in range(1, num_voters + 1):
        private_key, public_key = ECDSA_generate_keys(base_point, ORDER)
        voter_keys[voter_id] = (private_key, public_key)
    return voter_keys

# Step 2: Voting System Key Generation
def generate_system_keys():
    private_key, public_key = ECEG_generate_keys(base_point, ORDER)
    return private_key, public_key

# Step 3: Ballot Generation
def generate_ballot(candidate, public_key):
    # Generate a list with one '1' for the candidate and '0' for others
    ballot = [1 if i == candidate else 0 for i in range(NUM_CANDIDATES)]
    encrypted_ballot = [ECEG_encrypt(vote, public_key, base_point, ORDER) for vote in ballot]
    
    # Print the ballot 
    #print(f"Ballot for candidate {candidate}: {ballot}")
    
    return ballot, encrypted_ballot

# Step 4: Signature Generation
def sign_ballot(voter_private_key, encrypted_ballot):
    message = str(encrypted_ballot)
    nonce = random.randint(1, ORDER - 1)
    signature = ECDSA_sign(voter_private_key, message, nonce, base_point, ORDER)
    return signature

# Step 5: Signature Verification
def verify_signature(voter_public_key, encrypted_ballot, signature):
    message = str(encrypted_ballot)
    return ECDSA_verify(voter_public_key, message, signature, base_point, ORDER)

# Step 6: Homomorphic Tallying for Each Candidate
def tally_votes_per_candidate(encrypted_votes, system_private_key):
    combined_r = [(1, 0) for _ in range(NUM_CANDIDATES)]  # Start with point at infinity
    combined_c = [(1, 0) for _ in range(NUM_CANDIDATES)]
    
    # Aggregate encrypted votes for each candidate
    for encrypted_ballot in encrypted_votes:
        for i, (c1, c2) in enumerate(encrypted_ballot):
            combined_r[i] = add(*combined_r[i], *c1, p)
            combined_c[i] = add(*combined_c[i], *c2, p)
    
    # Decrypt results for each candidate
    total_votes = []
    for i in range(NUM_CANDIDATES):
        decrypted_point = ECEG_decrypt((combined_r[i], combined_c[i]), system_private_key)
        votes = bruteECLog(decrypted_point[0], decrypted_point[1], p)  # Recover vote count
        total_votes.append(votes)
        
        # Print the number of votes for the candidate
        #print(f"Candidate {i + 1} has {votes} vote(s).")
    
    return total_votes

# Updated Main Voting Process
def run_election():
    print("===== Electronic Voting Process =====")
    print(f"Number of Voters: {NUM_VOTERS}")
    print(f"Number of Candidates: {NUM_CANDIDATES}")
    print("Step 1: Generating keys for voters and the system...")
    
    # Generate keys for voters and system
    voter_keys = generate_voter_keys(NUM_VOTERS)
    system_private_key, system_public_key = generate_system_keys()
    print("Keys generated successfully.")
    
    encrypted_votes = []
    print("\nStep 2: Ballot generation and encryption for each voter...")
    for voter_id in range(1, NUM_VOTERS + 1):
        candidate = random.randint(0, NUM_CANDIDATES - 1)  # Randomly select a candidate
        voter_private_key, voter_public_key = voter_keys[voter_id]

        # Generate ballot and encrypt
        _, encrypted_ballot = generate_ballot(candidate, system_public_key)
        encrypted_votes.append(encrypted_ballot)
        print(f"Voter {voter_id} votes for Candidate {candidate + 1}.")

        # Sign ballot
        print(f"Signing the ballot for Voter {voter_id}...")
        signature = sign_ballot(voter_private_key, encrypted_ballot)
        assert verify_signature(voter_public_key, encrypted_ballot, signature), f"Signature invalid for Voter {voter_id}"
        print(f"Signature verified for Voter {voter_id}.\n")

    # Perform tallying
    print("Step 3: Homomorphic tallying of votes...")
    total_votes = tally_votes_per_candidate(encrypted_votes, system_private_key)
    print("\nFinal Results:")
    for candidate_id, votes in enumerate(total_votes):
        print(f"Candidate {candidate_id + 1}: {votes} votes")

    print("\nElection completed successfully!")

# Execute the election
if __name__ == "__main__":
    run_election()
