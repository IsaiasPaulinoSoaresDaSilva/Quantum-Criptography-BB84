# 🔐 Simulador de Criptografia Quântica – BB84

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://www.python.org/)  
[![Qiskit](https://img.shields.io/badge/Qiskit-optional-lightgrey)](https://qiskit.org/)  
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Este repositório contém um **simulador do protocolo BB84**, usado em **Distribuição de Chaves Quânticas (QKD – Quantum Key Distribution)**.  

O BB84 permite que duas partes (**Alice e Bob**) compartilhem uma chave secreta segura, mesmo na presença de um espião (**Eve**).  

O código implementa:  
- Bases aleatórias (Z/X)  
- Ataque **intercept-resend** de Eve  
- Ruído do canal (bit-flip)  
- Sifting (descartar bases diferentes)  
- Estimativa do **QBER** (Quantum Bit Error Rate)  
- **Privacy Amplification**  
- Execução rápida via **simulação clássica** ou **circuitos com Qiskit**  

---

## ⚙️ Instalação

Clone o repositório e instale as dependências:

```bash
gh repo clone IsaiasPaulinoSoaresDaSilva/Quantum-Criptography-BB84
cd bb84-simulador

# ambiente virtual (opcional)
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

# dependências
pip install -r requirements.txt
