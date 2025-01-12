from rfc7748 import add, computeVcoordinate
import random

# Importation des algorithme de chiffrement
from ecdsa import ECDSA_generate_keys, ECDSA_sign, ECDSA_verify
from ecelgamal import ECEG_generate_keys, ECEG_encrypt, ECEG_decrypt, bruteECLog

# Paramètres Curve 25519
p = 2**255 - 19
ORDER = 2**252 + 27742317777372353535851937790883648493
BaseU = 9
BaseV = computeVcoordinate(BaseU)
base_point = (BaseU, BaseV)

# Paramètres du vote : Nb de votants et nb de candidats
NUM_VOTERS = 10
NUM_CANDIDATES = 5

# Génération des clés publiques des votants
def generate_voter_keys(num_voters):
    # Liste de paire de clés
    voter_keys = {}
    # Pour chaque votants : on lui genere une paire de clés
    for voter_id in range(1, num_voters + 1):
        private_key, public_key = ECDSA_generate_keys(base_point, ORDER)
        voter_keys[voter_id] = (private_key, public_key)
    return voter_keys

# Génération de la paire de clé du système de vote
def generate_system_keys():
    private_key, public_key = ECEG_generate_keys(base_point, ORDER)
    return private_key, public_key

# Génération du scrutin
def generate_ballot(candidate, public_key):
    # Génération du scrutin
    ballot = [1 if i == candidate else 0 for i in range(NUM_CANDIDATES)]
    # print("ballot: ", ballot)

    # Chiffrement du scrutin
    encrypted_ballot = [ECEG_encrypt(vote, public_key, base_point, ORDER) for vote in ballot]
     
    return ballot, encrypted_ballot

# Signature du scrutin
def sign_ballot(voter_private_key, encrypted_ballot):
    message = str(encrypted_ballot)

    # On génère un nonce, puis on signe
    nonce = random.randint(1, ORDER - 1)
    signature = ECDSA_sign(voter_private_key, message, nonce, base_point, ORDER)
    return signature

# Signature
def verify_signature(voter_public_key, encrypted_ballot, signature):

    # Vérification du scrutin chiffré
    message = str(encrypted_ballot)
    return ECDSA_verify(voter_public_key, message, signature, base_point, ORDER)

# Décompte des votes pour chaque candidats
def tally_votes_per_candidate(encrypted_votes, system_private_key):
    combined_r = [(1, 0) for _ in range(NUM_CANDIDATES)]
    combined_c = [(1, 0) for _ in range(NUM_CANDIDATES)]
    
    for encrypted_ballot in encrypted_votes:
        for i, (c1, c2) in enumerate(encrypted_ballot):
            combined_r[i] = add(*combined_r[i], *c1, p)
            combined_c[i] = add(*combined_c[i], *c2, p)
    
    # Déchiffrement des résultats pour chaque candidats
    total_votes = []
    for i in range(NUM_CANDIDATES):
        decrypted_point = ECEG_decrypt((combined_r[i], combined_c[i]), system_private_key)
        votes = bruteECLog(decrypted_point[0], decrypted_point[1], p)
        total_votes.append(votes)
    
    return total_votes

# Exemple de vote électronique
def run_election():
    print("########## Vote électronique ##########\n")
    print(f"Nombres de votants: {NUM_VOTERS}")
    print(f"Nombres de condidats: {NUM_CANDIDATES}\n")
    print("##### Génération des paires de clés #####")
    
    # Génération des clés
    voter_keys = generate_voter_keys(NUM_VOTERS)
    system_private_key, system_public_key = generate_system_keys()
    print("Clés générées !\n")
    
    encrypted_votes = []
    print("##### Lancement du vote ! ######\n")
    for voter_id in range(1, NUM_VOTERS + 1):
        candidate = random.randint(0, NUM_CANDIDATES - 1) 
        voter_private_key, voter_public_key = voter_keys[voter_id]

        # Génération du scrution et chiffrement de celui ci
        _, encrypted_ballot = generate_ballot(candidate, system_public_key)
        encrypted_votes.append(encrypted_ballot)
        print(f"Le votant {voter_id} à voté pour le candidat n° {candidate + 1}.")

        # Signature du scrutin
        print(f"Signature du scrutin...")
        signature = sign_ballot(voter_private_key, encrypted_ballot)
        assert verify_signature(voter_public_key, encrypted_ballot, signature), "Signature invalide."
        print(f"Signature vérifiée !\n")

    # Décompte
    total_votes = tally_votes_per_candidate(encrypted_votes, system_private_key)

    # Affichage des résultats
    print("\n##### Résultats #####\n")
    for candidate_id, votes in enumerate(total_votes):
        print(f"Candidat n°{candidate_id + 1}: {votes} vote(s)")

    print("\n########## Fin des élections ! ##########")


run_election()
