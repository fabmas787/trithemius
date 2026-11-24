"""
Crew — multi-agent orchestration for Liber Primus analysis.
Trithemius coordinates a specialized team with distinct roles and cryptanalytic tools.

Usage:
    python3 agents/crew.py "Analyze page 56 rune patterns"
"""

import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

try:
    from crewai import Agent, Task, Crew, Process, LLM
    from crewai.tools import tool
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False
    Agent = Task = Crew = Process = LLM = None
    def tool(name=None):
        def decorator(fn):
            return fn
        return decorator

try:
    from ciphers.agrippa import (
        decode_runes, latin_to_rune, rune_to_prime, gematria_prime_sum,
        gematria_word_sums, rune_atbash, euler_totient, is_prime, prime_factors
    )
    from ciphers.kasiski import (
        estimate_key_length, crack_vigenere, vigenere_decode, consensus_key_length,
        rune_vigenere_decode, rune_vigenere_encode, rune_index_of_coincidence,
        estimate_rune_key_length, generate_primes, generate_fibonacci
    )
    from ciphers.al_kindi import ngram_score, rank_candidates, is_plausible_english, chi_squared_score
    from agents.ledger import log_attempt, has_been_tried, summary as ledger_summary
except ImportError:
    from agrippa import (
        decode_runes, latin_to_rune, rune_to_prime, gematria_prime_sum,
        gematria_word_sums, rune_atbash, euler_totient, is_prime, prime_factors
    )
    from kasiski import (
        estimate_key_length, crack_vigenere, vigenere_decode, consensus_key_length,
        rune_vigenere_decode, rune_vigenere_encode, rune_index_of_coincidence,
        estimate_rune_key_length, generate_primes, generate_fibonacci
    )
    from al_kindi import ngram_score, rank_candidates, is_plausible_english, chi_squared_score
    from ledger import log_attempt, has_been_tried, summary as ledger_summary
from config import CREWAI_MODEL_NAME, ACTIVE_PROVIDER, OLLAMA_HOST, get_api_key

local_llm = None
if CREWAI_AVAILABLE:
    if ACTIVE_PROVIDER == "ollama":
        local_llm = LLM(model=CREWAI_MODEL_NAME, base_url=OLLAMA_HOST)
    else:
        api_key = get_api_key(ACTIVE_PROVIDER)
        local_llm = LLM(model=CREWAI_MODEL_NAME, api_key=api_key) if api_key else LLM(model=CREWAI_MODEL_NAME)


# --- Cryptanalytic Tools for Agents ---

@tool("Decode Runes to Latin")
def decode_runes_tool(rune_string: str) -> str:
    """Convert Gematria Primus runes into Latin letters."""
    return decode_runes(rune_string)


@tool("Gematria Primus Prime Sum")
def gematria_sum_tool(text: str) -> str:
    """Calculate the sum of Gematria Primus prime values (2..109) for runes or Latin text."""
    total = gematria_prime_sum(text)
    word_sums = gematria_word_sums(text)
    words_summary = ", ".join(f"{w}: {s}" for w, s in word_sums[:8])
    return f"Total Gematria Sum: {total} (Totient: {euler_totient(total)}, Prime?: {is_prime(total)})\nWord breakdown: {words_summary}"


@tool("Rune Vigenere Modulo 29")
def rune_vigenere_tool(ciphertext_runes: str, key: str) -> str:
    """
    Decrypt or test a Vigenere cipher directly on runes (mod 29).
    Key can be a word (e.g. 'DIVINITY') or comma-separated integers.
    """
    decoded_runes = rune_vigenere_decode(ciphertext_runes, key)
    decoded_latin = decode_runes(decoded_runes)
    passed, metrics = is_plausible_english(decoded_latin)
    return (
        f"Decoded Runes: {decoded_runes}\n"
        f"Decoded Latin: {decoded_latin}\n"
        f"Plausibility: {metrics['verdict']} (Chi2: {metrics['chi_squared']}, Ngram: {metrics['ngram_score']}, Words: {metrics['word_ratio']})"
    )


@tool("Rune Atbash")
def rune_atbash_tool(rune_string: str) -> str:
    """Invert runes via Gematria Primus Atbash (index -> 28 - index)."""
    inverted = rune_atbash(rune_string)
    latin = decode_runes(inverted)
    return f"Inverted Runes: {inverted}\nDecoded Latin: {latin}"


@tool("Sacred Math and Primes")
def sacred_math_tool(number_str: str) -> str:
    """Calculate Euler totient phi(n), primality, and prime factors for a number."""
    try:
        n = int(number_str.strip())
        tot = euler_totient(n)
        prime = is_prime(n)
        factors = prime_factors(n)
        return f"Number: {n} | Prime: {prime} | Totient phi({n}): {tot} | Factors: {factors}"
    except Exception as e:
        return f"Error: {e}"


@tool("Estimate Key Length")
def key_length_tool(ciphertext: str) -> str:
    """Estimate Vigenere key length using IoC and Friedman consensus test."""
    has_runes = any(ord(c) >= 0x16A0 and ord(c) <= 0x16FF for c in ciphertext)
    if has_runes:
        ranks = estimate_rune_key_length(ciphertext, max_len=20)
        return f"Rune IoC key length candidates (length, IoC): {ranks[:5]}"
    res = consensus_key_length(ciphertext)
    return str(res)


@tool("Score Plaintext Plausibility")
def plausibility_tool(candidate: str) -> str:
    """Score how English-like a candidate plaintext is using chi-squared, n-grams, and vocabulary."""
    passed, metrics = is_plausible_english(candidate)
    return f"Verdict: {metrics['verdict']} | Chi-Squared: {metrics['chi_squared']} | Ngram Score: {metrics['ngram_score']} | Word Ratio: {metrics['word_ratio']}"


@tool("Check Hypothesis Ledger")
def ledger_check_tool(page: str, method: str, key: str = "") -> str:
    """Check whether a given page/method/key combination has already been tried."""
    tried = has_been_tried(page, method, key or None)
    return f"Already tried: {tried}" if tried else "Not yet tried — safe to attempt."


# --- Agents Configuration ---

bodleian = Agent(
    role="Corpus Librarian",
    goal="Retrieve relevant passages from the local research corpus. Never speculate "
         "or offer opinions on whether a decryption is correct — only supply raw material.",
    backstory="Named for Thomas Bodley, founder of the Bodleian Library. Meticulous, "
              "neutral, and allergic to speculation.",
    llm=local_llm,
    verbose=True,
)

bacon = Agent(
    role="Web Researcher",
    goal="Find and summarize current, relevant information from the web about Cicada "
         "3301 and Liber Primus. Never fabricate sources.",
    backstory="Named for Roger Bacon, medieval empiricist. Trusts observation over authority.",
    llm=local_llm,
    verbose=True,
)

cryptanalyst = Agent(
    role="Cryptanalyst",
    goal="Apply cryptographic techniques (Gematria Primus, Vigenere mod-29, rune Atbash, "
         "Euler totients, frequency scoring) using tools rather than guessing.",
    backstory="Embodies Agrippa (gematria & sacred math), Kasiski (Vigenere & key analysis), "
              "and Al-Kindi (frequency & statistical analysis) as one master cryptanalyst.",
    tools=[
        decode_runes_tool, gematria_sum_tool, rune_vigenere_tool,
        rune_atbash_tool, sacred_math_tool, key_length_tool, plausibility_tool
    ],
    llm=local_llm,
    verbose=True,
)

archivist = Agent(
    role="Hypothesis Archivist",
    goal="Check the ledger before any attempt is proposed, and ensure nothing already "
         "tried and failed gets re-suggested.",
    backstory="Keeps the lab notebook. Has no patience for repeated dead ends.",
    tools=[ledger_check_tool],
    llm=local_llm,
    verbose=True,
)

trithemius = Agent(
    role="Lead Orchestrator",
    goal="Coordinate the team, synthesize findings into a clear, mathematically sound "
         "final answer, and flag genuine uncertainty rather than overclaiming progress.",
    backstory="Named for Johannes Trithemius, father of Western cryptography. Rigorous, "
              "skeptical of unverified decryptions, allergic to false positives.",
    llm=local_llm,
    verbose=True,
)


def build_crew(task_description: str) -> Optional[Any]:
    if not CREWAI_AVAILABLE:
        print("[!] CrewAI is not installed. Multi-agent crew functionality is unavailable.")
        return None
    research_task = Task(
        description=f"Gather relevant background for: {task_description}",
        expected_output="A concise summary of relevant corpus material.",
        agent=bodleian,
    )

    web_task = Task(
        description=f"Search for live updates or known solvers' consensus on: {task_description}",
        expected_output="A summary of live web findings or note 'nothing new'.",
        agent=bacon,
    )

    ledger_task = Task(
        description=f"Check what methods and keys have already been tried for: {task_description}.",
        expected_output="List of previously tested hypotheses to avoid, or 'nothing on record'.",
        agent=archivist,
    )

    crypto_task = Task(
        description=f"Apply cryptographic analysis to: {task_description}. "
                     "Use the cryptographic tools (Rune Vigenere, Gematria Sum, Sacred Math) "
                     "to test hypotheses quantitatively.",
        expected_output="Decryption candidates found with statistical scores and exact methods used.",
        agent=cryptanalyst,
        context=[research_task, web_task, ledger_task],
    )

    synthesis_task = Task(
        description="Synthesize all findings into an honest, objective summary. "
                    "Highlight whether any candidate meets statistical significance or needs "
                    "adversarial verification.",
        expected_output="A final research assessment with clear next steps.",
        agent=trithemius,
        context=[research_task, web_task, ledger_task, crypto_task],
    )

    return Crew(
        agents=[bodleian, bacon, archivist, cryptanalyst, trithemius],
        tasks=[research_task, web_task, ledger_task, crypto_task, synthesis_task],
        process=Process.sequential,
        verbose=True,
    )


if __name__ == "__main__":
    task_desc = " ".join(sys.argv[1:]) or "Analyze the cryptographic structure of Liber Primus"
    crew = build_crew(task_desc)
    if crew is None:
        sys.exit(1)
    result = crew.kickoff()
    print("\n\n=== TRITHEMIUS CREW REPORT ===\n")
    print(result)
