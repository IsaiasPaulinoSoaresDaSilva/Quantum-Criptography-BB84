"""
Simulador BB84 de Distribuição de Chaves Quânticas (QKD)
--------------------------------------------------------

Objetivo
1- Simular a geração de uma chave secreta entre Alice e Bob usando o protocolo BB84.
2- Permitir inserir ruído do canal e um atacante (Eve) com intercept-resend.
Realizar:
  1) Preparação e medição em bases aleatórias (Z/X)
  2) Sifting (descartar posições de bases diferentes)
  3) Estimativa do QBER
  4) (Opcional) Abortar se QBER acima do limiar
  5) Privacy amplification (reduzir chave com SHAKE-256, aproximando a taxa segura)

Observações
- Este código é resultado de um projeto de pesquisa. A reconciliação de erros (p.ex. Cascade/LDPC) não está implementada;
  em vez disso, exemplificou-sea etapa de privacidade (privacy amplification) considerando a
  fração de informação potencialmente vazada indicada pelo QBER (limite Devetak–Winter aproximado).
- Opcionalmente, é possível usar o Qiskit para montar e executar os circuitos qubit-a-qubit;
  por padrão, usa-se uma simulação clássica eficiente que replica estatísticas do BB84.

Dependências
- numpy, hashlib. (Opcional: qiskit)
- Importante ver o arquivo de requirements

Uso rápido
---------
python BB84_QKD_Simulador_com_Privacy_Amplification.py

ou em Python:
from BB84_QKD_Simulador_com_Privacy_Amplification import run_bb84
res = run_bb84(N=10_000, p_noise=0.01, p_eve=0.0, abort_threshold=0.11, use_qiskit=False)
print(res)
"""
from __future__ import annotations
import math
import os
import secrets
from dataclasses import dataclass
from typing import Optional, Tuple, Dict

import numpy as np

try:
    # Qiskit é opcional. Se não estiver instalado, rodamos pelo caminho clássico.
    from qiskit import QuantumCircuit
    from qiskit_aer import Aer
    _HAS_QISKIT = True
except Exception:
    _HAS_QISKIT = False


@dataclass
class BB84Result:
    N: int
    p_noise: float
    p_eve: float
    abort_threshold: float
    use_qiskit: bool
    sift_fraction: float
    sift_len: int
    qber: float
    final_key_bits: int
    final_key_hex: str
    aborted: bool


def binary_entropy(p: float) -> float:
    """Entropia binária H2(p) com salvaguardas numéricas."""
    p = min(max(p, 1e-12), 1 - 1e-12)
    return -p * math.log2(p) - (1 - p) * math.log2(1 - p)


def shake256_bits(data: bytes, n_bits: int) -> bytes:
    """Gera n_bits via SHAKE256 (XOF)."""
    import hashlib
    out_bytes = (n_bits + 7) // 8
    digest = hashlib.shake_256(data).digest(out_bytes)
    if n_bits % 8:
        # zera os bits extras do último byte
        mask = (0xFF << (8 - (n_bits % 8))) & 0xFF
        digest = bytearray(digest)
        digest[-1] &= (~mask) & 0xFF
        digest = bytes(digest)
    return digest


def prepare_and_measure_classical(bits: np.ndarray, bases_a: np.ndarray, bases_b: np.ndarray,
                                  p_noise: float, p_eve: float, rng: np.random.Generator) -> np.ndarray:
    """
    Simula o resultado de Bob nos fundamentos do BB84, incluindo:
    - Ataque Eve intercept-resend com probabilidade p_eve (por fóton)
    - Ruído de canal (bit-flip) com probabilidade p_noise

    Retorna o array de bits medidos por Bob (tamanho N).
    """
    N = bits.size
    bob_results = np.empty(N, dtype=np.uint8)

    # Modelo simples de Eve: intercepta com prob p_eve. Se intercepta, mede em base aleatória,
    # reenvia o estado preparado conforme o bit que ela mediu e a base dela.
    eve_intercepts = rng.random(N) < p_eve
    eve_bases = rng.integers(0, 2, size=N, dtype=np.uint8)  # 0=Z, 1=X

    # Sem Qiskit: regras de BB84 estatísticas
    # 1) Se Bob mede na mesma base que o estado foi preparado, ele recupera o bit (salvo ruído ou erro introduzido por Eve)
    # 2) Se mede em base diferente, resultado é aleatório (50/50)

    # Primeiro, bits e bases que chegam a Bob (após possível Eve)
    bits_to_bob = bits.copy()
    bases_to_bob = bases_a.copy()

    # Onde Eve intercepta, ela mede e reenvia
    if eve_intercepts.any():
        # Eve mede: se a base dela = base de Alice, ela lê o bit correto; senão aleatório
        same_base_eve_alice = eve_bases == bases_a
        # resultado da Eve
        eve_results = np.where(same_base_eve_alice, bits,
                               rng.integers(0, 2, size=N, dtype=np.uint8))
        # Eve reenvia conforme a base dela e o bit medido
        bits_to_bob[eve_intercepts] = eve_results[eve_intercepts]
        bases_to_bob[eve_intercepts] = eve_bases[eve_intercepts]

    # Bob mede
    same_base_bob = bases_to_bob == bases_b
    random_bits = rng.integers(0, 2, size=N, dtype=np.uint8)
    bob_results = np.where(same_base_bob, bits_to_bob, random_bits)

    # Ruído de canal: bit-flip com prob p_noise
    flips = rng.random(N) < p_noise
    bob_results ^= flips.astype(np.uint8)

    return bob_results


def prepare_and_measure_qiskit(bits: np.ndarray, bases_a: np.ndarray, bases_b: np.ndarray,
                               p_noise: float, p_eve: float, rng: np.random.Generator) -> np.ndarray:
    """
    Implementação qubit-a-qubit via Qiskit (qasm_simulator, sem ruído físico customizado).
    O ruído de canal é aproximado com flips clássicos pós-medida; Eve é modelada classicamente.
    Essa via é mais lenta, mas mostra o pipeline com circuitos reais.
    """
    if not _HAS_QISKIT:
        return prepare_and_measure_classical(bits, bases_a, bases_b, p_noise, p_eve, rng)

    backend = Aer.get_backend('aer_simulator')
    results = np.empty(bits.size, dtype=np.uint8)

    # Aplicamos a mesma lógica de Eve antes do circuito (intercept-resend)
    eve_intercepts = rng.random(bits.size) < p_eve
    eve_bases = rng.integers(0, 2, size=bits.size, dtype=np.uint8)

    bits_to_bob = bits.copy()
    bases_to_bob = bases_a.copy()

    if eve_intercepts.any():
        same_base_eve_alice = eve_bases == bases_a
        eve_results = np.where(same_base_eve_alice, bits,
                               rng.integers(0, 2, size=bits.size, dtype=np.uint8))
        bits_to_bob[eve_intercepts] = eve_results[eve_intercepts]
        bases_to_bob[eve_intercepts] = eve_bases[eve_intercepts]

    # Agora, para cada fóton, montamos um circuito 1-qubit:
    # - Preparo: |0>, se base Z e bit 1 -> X; se base X e bit 0 -> H; se base X e bit 1 -> H seguido de X
    # - Medida: se Bob em X -> H antes de medir; sempre medir em Z
    from qiskit import transpile

    circuits = []
    for b, ba, bb in zip(bits_to_bob, bases_to_bob, bases_b):
        qc = QuantumCircuit(1, 1)
        if ba == 0:  # Z-basis
            if b == 1:
                qc.x(0)
        else:  # X-basis
            qc.h(0)
            if b == 1:
                qc.x(0)
        if bb == 1:  # medir em X => rotaciona de volta com H
            qc.h(0)
        qc.measure(0, 0)
        circuits.append(qc)

    tqc = transpile(circuits, backend)
    job = backend.run(tqc, shots=1)
    job_res = job.result()

    for i, qc in enumerate(circuits):
        counts = job_res.get_counts(i)
        # counts ex: {'0':1} ou {'1':1}
        bit = 1 if counts.get('1', 0) > 0 else 0
        results[i] = bit

    # Aplica ruído de canal como bit-flip clássico pós-medida
    flips = rng.random(bits.size) < p_noise
    results ^= flips.astype(np.uint8)
    return results


def run_bb84(N: int = 10_000,
             p_noise: float = 0.01,
             p_eve: float = 0.0,
             abort_threshold: float = 0.11,
             use_qiskit: bool = False,
             seed: Optional[int] = None) -> BB84Result:
    """Executa uma rodada BB84 de tamanho N.

    Params
    ------
    N : número de qubits/fótons enviados
    p_noise : probabilidade de flip no canal (ruído)
    p_eve : probabilidade de interceptação por Eve
    abort_threshold : limiar de QBER para abortar
    use_qiskit : usar (ou não) a via de circuitos com Qiskit
    seed : semente RNG para reprodutibilidade
    """
    rng = np.random.default_rng(seed)

    # 1) Alice escolhe bits e bases
    bits_a = rng.integers(0, 2, size=N, dtype=np.uint8)
    bases_a = rng.integers(0, 2, size=N, dtype=np.uint8)  # 0=Z, 1=X

    # 2) Bob escolhe bases
    bases_b = rng.integers(0, 2, size=N, dtype=np.uint8)

    # 3) Transmissão/medida
    if use_qiskit:
        bob_results = prepare_and_measure_qiskit(bits_a, bases_a, bases_b, p_noise, p_eve, rng)
    else:
        bob_results = prepare_and_measure_classical(bits_a, bases_a, bases_b, p_noise, p_eve, rng)

    # 4) Sifting: manter apenas onde bases coincidem
    mask = bases_a == bases_b
    sift_a = bits_a[mask]
    sift_b = bob_results[mask]
    sift_len = sift_a.size
    sift_fraction = sift_len / N if N else 0.0

    # 5) Estimar QBER a partir de uma amostra pública (aqui, simples: comparamos tudo para didática)
    # Em um protocolo real, revela-se apenas uma fração aleatória para estimativa.
    errors = (sift_a != sift_b).sum()
    qber = errors / sift_len if sift_len else 0.0

    # 6) Se QBER acima do limiar, aborta
    aborted = qber > abort_threshold

    # 7) Privacy amplification: estima tamanho seguro da chave final
    # Devetak–Winter bound (aprox.): r >= 1 - 2 H2(Q)
    # Tamanho final = floor(sift_len * max(0, 1 - 2*H2(Q)))
    if sift_len == 0:
        final_bits = 0
    else:
        rate = max(0.0, 1.0 - 2.0 * binary_entropy(qber))
        final_bits = int(math.floor(sift_len * rate))

    # 8) Deriva a chave final com SHAKE-256 sobre (sift_a || salt) e trunca para final_bits
    if final_bits > 0 and not aborted:
        salt = secrets.token_bytes(32)
        data = bytes(sift_a.tolist()) + salt
        final_key = shake256_bits(data, final_bits)
        final_hex = final_key.hex()
    else:
        final_bits = 0
        final_hex = ""

    return BB84Result(
        N=N,
        p_noise=p_noise,
        p_eve=p_eve,
        abort_threshold=abort_threshold,
        use_qiskit=use_qiskit and _HAS_QISKIT,
        sift_fraction=sift_fraction,
        sift_len=sift_len,
        qber=qber,
        final_key_bits=final_bits,
        final_key_hex=final_hex,
        aborted=aborted,
    )


def _pretty_print(res: BB84Result) -> str:
    lines = [
        "===== Resultado BB84 =====",
        f"N enviados         : {res.N}",
        f"p_noise             : {res.p_noise:.4f}",
        f"p_eve               : {res.p_eve:.4f}",
        f"abort_threshold     : {res.abort_threshold:.2%}",
        f"usando Qiskit?      : {res.use_qiskit}",
        f"fração sifting      : {res.sift_fraction:.2%}",
        f"tamanho sifting     : {res.sift_len}",
        f"QBER                : {res.qber:.2%}",
        f"abordado?           : {res.aborted}",
        f"chave final (bits)  : {res.final_key_bits}",
        f"chave final (hex)   : {res.final_key_hex[:64]}{'...' if len(res.final_key_hex)>64 else ''}",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    # Execução de demonstração
    res = run_bb84(
        N=20_000,
        p_noise=0.02,         # ~2% de ruído
        p_eve=0.00,           # 0 = sem ataque; tente 0.2 para ver QBER subir
        abort_threshold=0.11, # limiar típico ~11%
        use_qiskit=False,     # True se quiser usar Qiskit (mais lento)
        seed=42,
    )
    print(_pretty_print(res))
