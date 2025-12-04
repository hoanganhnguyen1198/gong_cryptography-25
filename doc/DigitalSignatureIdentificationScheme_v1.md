# PQC: Digital Signature - Identification Scheme

Status: In progress
Type: Studies
Fields: Technology

**Hemingway Bridge:**

- [x]  Provide Proof for Theorem 12.10
- [x]  Add the observation on the Schnorr identification scheme
- [ ]  Provide Proof for Theorem 12.11
- [ ]  Add the Code section

---

# Theory:

**Chapter 12: Digital Signature**

12.5. Signatures from the Discrete-Logarithm Problem:

## Identification Schemes:

---

Identification Scheme:

- Interactive protocol
- Allow one party to prove its identity to another

Description:

- Two parties
    - **Prover** - **Verifier**
- The verifier only knows the public key of the prover
- **Identification sucess means the verifier is communicating with the intended prover**
- The protocol
    - Private key $sk$ - Public key $pk$
    - Three algorithms: $P_1$, $P_2$, $V$
    - Initial message $I$ and some state $st$
    - Challenge $r$ chosen from some set $\Omega_{pk}$
    - Response $s$
    
    ![image.png](img/DigitalSignature/identification_scheme_0.png)
    

The scheme is **non-degenerate**

- There are many possible initial message $I$, and none has a high probability of being sent
    
    $$
    \forall sk \, \land \, \forall I \quad|\quad \textnormal{Pr}[P_1(sk) = I] = \textnormal{negl}(n) 
    $$
    

Security requirement

- An adversary who does not know the prover’s $sk$ should not be able to fool the verifier into accepting

### The identification experiment $\textnormal{Ident}_{A,\Pi}(n)$

Let $\Pi = (\textnormal{Gen},P_1, P_2, V)$ be an identification scheme

Consider an adversary $A$ and parameter $n$

The identification experiment $\textnormal{Ident}_{A,\Pi}(n)$

1. $\textnormal{Gen}(1^n)$ is run to obtain keys $(sk, pk)$
2. $A$  is given $pk$ and access to an oracle $\textnormal{Trans}_{sk}$ that it can query as often as it likes
3. At any point during the experiment, $A$ outputs a message $I$
A uniform challenge $r \in \Omega_{pk}$ is chosen and given to $A$, who responds with some $s$
4. The experiment output $1$ iff $V(pk, r, s) \overset{?}{=} I$

### Definition 12.8:

An identification scheme $\Pi = (\textnormal{Gen},P_1, P_2, V)$ is secure against a passive attack, or just secure, if $\forall$ PPT $A$, $\exist$ a negligible function $\textnormal{negl}$ such that

$$
\textnormal{Pr}[\textnormal{Ident}_{A,\Pi}(n) = 1] \leq \textnormal{negl}(n)
$$

## Fiat-Shamir Transformation:

---

Construct a identification scheme (interactive) to a signature scheme.

The signer act as a prover, running the identification protocol by itself

### Construction 12.9:

Let $(\textnormal{Gen}_{id}, P_1, P_2, V)$ be an identification scheme

Construct the signature as follows:

- $\textnormal{Gen}$:
    - Input $1^n$, run $\textnormal{Gen}_{id}(1^n)$ to obtain $pk, sk$
    - $pk$ specifies a set of challenges $\Omega_{pk}$
    - An implicit function $H: \{0, 1\}^* \rightarrow \Omega_{pk}$ is specified
- $\textnormal{Sign}$:
    - Input $sk$ and a message $m \in \{0,1\}^*$
    - Do
        1. Compute $(I,\textnormal{st}) \leftarrow P_1(sk)$
        2. Compute $r := H(I,m)$
        3. Compute $s:= P_2(sk,\textnormal{st},r)$
    - Output the signature $(r, s)$
- $\textnormal{Vrfy}$:
    - Input $pk$, message $m$, and a signature $(r,s)$
    - Compute $I:=V(pk,r,s)$
    - Output 1 iff $H(I,m) \overset{?}{=} r$

### Theorem 12.10:

<aside>
📌

Let $\Pi$ be an identification scheme, let $\Pi'$ be the signature scheme that results by applying the Fiat-Shamir transform to it.

If $\Pi$ is secure and $H$ is modeled as a random oracle, then $\Pi'$ is secure.

</aside>

- **PROOF:**
    
    $A'$ be a PPT adversary attacking $\Pi'$, with $q = q(n)$ an upper bound on the number of query $A'$ makes to $H$.
    
    Assumptions:
    
    - $A'$ makes any given query to $H$ only once
    - After being given a signature $(r, s)$ on a message $m$ with $V(pk,r,s)=I$, $A'$ never queries $H(I,m)$
    - If $A'$ outputs a forged signature $(r, s)$ on a message $m$ with $V(pk,r,s)=I$, $A'$ would had previously queried $H(I,m)$
    
    Construct $A$ that uses $A'$ as a subroutine and attack the identification scheme $\Pi$.
    
    Algorithm $A$:
    
    Given $pk$ and access to an oracle $\textnormal{Trans}_{sk}$
    
    1. Choose uniform $j \in \{1,...,q\}$
    2. Run $A'(pk)$ as follows
        
        When $A'$ makes it *i*th random-oracle query $H(I_i, m_i)$:
        
        - If $i = j$, output $I_j$ and receive in return a challenge $r$. Return $r$ to $A'$  as the answer
        - If $i \neq j$, choose a uniform $r \in \Omega_{pk}$ and return $r$ as the answer
        
        When $A'$ requests a signature on $m$:
        
        1. Query $\textnormal{Trans}_{sk}$ to obtain a transcript $(I, r,s)$  of an honest execution of the protocol
        2. Return the signature $(r,s)$
    3. If $A'$ outputs a forged signature $(r,s)$ on a message $m$, compute $I:=V(pk,r,s)$ and check if $(I,m) \overset{?}{=}(I_j,m_j)$. If so, output $s$. Otherwise, abort.
    
    Overall Analysis:
    
    - The view of $A'$ when run as a subroutine by $A$ in the experiment $\textnormal{Ident}_{A,\Pi}(n)$ is *almost* identical to the view of $A'$ in experiment $\textnormal{Sig-forge}_{A',\Pi'}(n)$.
        - All $H$-queries $A'$ makes are answered with a uniform value from $\Omega_{pk}$
        - All signing queries $A'$ makes are answered with valid signatures
        - There might be an inconsistency in the answer $A'$ receives from its queries to $H$
            
            If $A$ ever answers a signing query for a message $m$ using a transcript $(I, r,s)$ for which:
            
            - $H(I,m)$ is already defined ($A'$ had previously queried $(I,m)$ to $H$), and
            - $H(I,m) \neq r$
            
            → If $\Pi$ is non-degenerate, this will only ever happen with negligible probability
            
    - The probability that $A'$ outputs a forgery when run as a subroutine by $A$ is $\textnormal{Sig-forge}_{A',\Pi'}(n) - \textnormal{negl}(n)$ for some negligible function $\textnormal{negl}$.
    
    Detailed Analysis:
    
    - Consider an execution of $\textnormal{Ident}_{A,\Pi}(n)$ in which $A'$ outputs a forged signature $(r, s)$ on a message $m$, let $I:=V(pk, r,s)$
    - Since $j$ is uniform and independent, $\textnormal{Pr}[(I,m)=(I_j,m_j)] = 1/q$ (even when $A'$ outputs a forgery).
        
        ← Assumption #3
        
    - When both events happent, $A$ successfully impersonates the prover.
        - $A$ sends $I_j$ as its initial message, receives $r$, and responds with $s$.
        - But $H(I_j, m_j)=r$ and $V(pk,r,s)=I$
    - Therefore
        
        $$
        \textnormal{Pr}[\textnormal{Ident}_{A,\Pi}(n)=1]\ge \frac{1}{q(n)}.(\textnormal{Pr}[\textnormal{Sig-forge}_{A',\Pi'}(n) =1]- \textnormal{negl}(n))
        $$
        
        or
        
        $$
        \textnormal{Pr}[\textnormal{Sig-forge}_{A',\Pi'}(n) =1] \le q(n).\textnormal{Pr}[\textnormal{Ident}_{A,\Pi}(n)=1] + \textnormal{neql}(n)
        $$
        
    - If $\Pi$ is secure, $\textnormal{Pr}[\textnormal{Ident}_{A,\Pi}(n)=1]$ is negligible.
    - Since $q(n)$ is polynomial, $\textnormal{Pr}[\textnormal{Sig-forge}_{A',\Pi'}(n) =1]$ is also neglible.
    - Because $A'$ was arbitrary, this means **$\Pi'$ is secure**.

## Schnorr Signature:

---

### The Schnorr Identification Scheme:

The Schnorr identification scheme is based on hardness of the discrete-logarithm problem

**Security Model:**

- Let $G$ be a polynomial-time algorithm taking $1^n$ as input and outputing a description of a cyclic group $\mathbb{G}$, its order $q$ (with $||q|| = n$), and a generator $g$
- Key generation:
    - The prover runs $G(1^n)$ to obtain $(\mathbb{G},q,g)$
    - Choose a uniform $x \in \mathbb{Z}_q^*$ and set $y:=g^x$
    - Public key: $(\mathbb{G},q,g,y)$
    - Private key: $x$
- Execution:
    - Prover:
        - Choose a uniform $k \in \mathbb{Z}_q^*$ and set $I:=g^k$
        - Send I as the initial message
    - Verifier:
        - Choose and send a uniform challenge $r \in \mathbb{Z}_q$
    - Prover:
        - Compute $s:=[rx+k\;\textnormal{mod}\,q]$
    - Verifier:
        - Accept iff $g^s.y^{-r}\overset{?}{=}I$
    
    ![image.png](img/DigitalSignature/identification_scheme_1.png)
    

$I$  is uniform in $\mathbb{G}$ → **The scheme is non-degenerate**

**Correctness:**

$$
g^s.y^{-r}=g^{rx+k}.(g^x)^{-r} = g^k=I
$$

**Observation:**

- Passive eavesdropping does not help the attacker.
    - The attacker can ***simulate*** transcripts of honest executions on its own based only on $pk$ by
        - choosing uniform and independent $r,s \in \mathbb{Z}_q$, then
        - setting $I:=g^s.y^{-r}$
    - Consider an attacker who gets a public key $y$, sends an initial message $I$, is given $r$, then must send a response $s$ for which $g^s.y^{-r}=I$
        - If so, it must be able to compute correct responses $s_1$, $s_2$ to at least two different challenges $r_1,r_2 \in \mathbb{Z}_q$ such that $g^{s_1}.y^{-r_1}=I=g^{s_2}.y^{-r_2}$ and so $g^{s_1-s_2}=y^{r_1-r_2}$
        - But this implies that the attacker can implicitly compute the discrete logarithm
            
            $$
            \textnormal{log}_gy = [(s_1-s_2).(r_1-r_2)^{-1}\textnormal{mod}q]
            $$
            
            contradicting the assumed hardness of the discrete-logarithm problem.
            

### **Theorem 12.11:**

<aside>
📌

If the discrete-logarithm problem is hard relative to $G$, then the Schnorr identification scheme is secure.

</aside>

- **PROOF:**

### Schnorr Signature Construction:

Let $G$ be as described above

- $\textnormal{Gen}$:
    - Run $G(1^n)$ to obtain $(\mathbb{G},q,g)$
    - Choose a uniform $x \in \mathbb{Z}_q$ and set $y:=g^x$
    - Private key: $x$
    - Public key: $(\mathbb{G},q,g,y)$
    - $H:\{0,1\}^* \rightarrow \mathbb{Z}_q$ is implicitly specified
- $\textnormal{Sign}$:
    - Input a private key $x$ and a message $m \in \{0,1\}^*$
    - Choose a uniform $k \in \mathbb{Z}_q$ and set $I:=g^k$
    - Compute $r:=H(I,m)$
    - Compute $s:=[rx + k\,\textnormal{mod}\,q]$
    - Output signature $(r,s)$
- $\textnormal{Vrfy}$:
    - Input a public key $(\mathbb{G},q,g,y)$, a message $m$, a signature $(r,s)$
    - Compute $I:=g^s.y^{-r}$
    - Output $1$ iff $H(I,m)\overset{?}{=} r$