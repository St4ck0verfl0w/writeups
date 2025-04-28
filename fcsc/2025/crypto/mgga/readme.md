
# Table of Contents

1.  [Introduction](#orge439b2c)
2.  [The GEA1 algorithms](#org4eae256)
3.  [Back to the challenge](#org7564aba)
4.  [Conclusion](#orgda5d5cc)



<a id="orge439b2c"></a>

# Introduction

This write-up will present a solution for &ldquo;Make GEA Great Again&rdquo;, considered the hardest challenge out of 9th cryptographic challenges at of the France CyberSecurity Challenge (FCSC) 2025.

In this challenge is given the source code for a strange LFSR-like structure that will have to be analysed. Unlike traditional challenges, the goal here is to break the system by introducing a trapdoor in the system with specific coefficients.


<a id="org4eae256"></a>

# The GEA1 algorithms

While I had never heard of the GEA algorithm before, I figured a quick look to the literature would not hurt. I managed to find two papers that described it pretty well:  <https://eprint.iacr.org/2021/819.pdf>, and more importantly <https://eprint.iacr.org/2021/829.pdf>, that explains the method that can be used to generate the polynomials. I will come back to the second one later.

I will only describe GEA1 from a high level, then proceed to explain how the attack was theorized and built.

GEA is a proprietary stream cipher that was originally designed for General Packet Radio Service (GPRS). GEA1 uses three internal Linear Feedback Shift Registers (LFSR) that are concurrently updated to generate pseudorandom bits sequences that are fed to a boolean function. In this write-up, I will call the three LFSRs A, B and C, just like the paper.

A, B and C respectively have an internal state size of 31, 32 and 33 bits, initialized from a 64-bit secret, which should lead to a maximal joint initial entropy of $64$ bits. The initialization is performed through a non-linear feedback shift register S with a 64-bit internal state, as followed:

-   From the 64-bit key, a 32-bit IV, and a bit direction (0 in our case), build the keystream $S_0 = IV+0+key+[0]*128$
-   Clock this keystream into S, leading to a 64 bit secret state $s$
-   Clock the $s$ into A, which now has at most 31 bits of entropy
-   Shift $s$ by some amount, then clock it into B, which now has at most 32 bits of entropy
-   Shift $s$ by some other amount, then clock it into C, which now has at most 33 bits of entropy

This leads to an apparently robust stream cipher. However, it was realized by the scientific community that the primitive polynomials used for the LFSR are far from random. They allow a joint distribution of the states A and C with far less entropy. Since the LFSR clocks and the initial state shift are linear operation, we can deterministically build 3 matrices $M_A$, $M_B$ and $M_C$ (that only depends on the companion matrix of the LFSR and the shift used) such that the state of register $X$ after shifting then clocking s in X is going to be $M_X.s$. It turns out that, with the chosen choices of polynomials and shifts, $Ker(M_A)\bigcap Ker(M_C)$ has dimension 24. This essentially means that the joint distribution of A and C actually has only 40 bits of entropy. From this, a divide and conquer attack can be mounted to retrieve the initial state s, from which it is straightforward to retrieve the key by backclocking and clocking the nLFSR $S$.

The method requires $2^{37}$ GEA1 evaluations in order to generate $2^8$ tables with $2^{24}$ entries of size 89-bits, then $2^{40}$ bits of bruteforce.

The article provides source code that can serve as a base for our own analysis. They also showed that this kind of backdoor does not appear at random. This mean we are going to have to work a bit in order to find the new polynomials.


<a id="org7564aba"></a>

# Back to the challenge

In this challenge, once the polynomials are set, we are given $2^{18}$ bitstreams with known IV but the same unknown key $k$. From that, we are supposed to retrieve the session key $k$. The implemented code is very similar to the GEA1 algorithm as presented in the article. However, there are two majors changes:

-   First, the shift amounts are different. In the original GEA1 version, $B$ takes as input the keystream shifted $16$ times and $C$ takes as input $s$ shifted $32$ times. In our situation, the shifts are much more symmetric, with $21$ and $42$ bit shifts for $B$ and $C$.
-   But most importantly, in this challenge, WE are the one choosing the polynomials of the LFSR. This means that we are going to be the bad guys designing trapdoored cryptographic scheme! Isn&rsquo;t that cool?

Also, there seems to be a difference of endianness between the article&rsquo;s source code and the challenge. This is not very important, since changing endianness really is a linear operation, but it must be taken into account that a great focus will be required during implementation in order to keep the endianness consistent throughout the attack (I speak from experience). It will not however have any impact on the theory.


## First approach, how were the original polynomials found

The first question is actually to understand how the initial trapdoor polynomials were implemented, in order to build our own. In <https://eprint.iacr.org/2021/829.pdf>, they provide a very nice analysis on how to actually build the polynomials with shared kernels.

Let&rsquo;s change perspective, and start from a vector $t$ in the joint kernel $T_{A,B,r}$ where $A$ and $B$ are updated with polynomials $f$, $g$ and the initial state is shifted by $r$ bits before begin plugged into $B$. The authors of the article proved that $f$ must divide $\sum_{i=0}^{63} t_i X^{64-i} = U_f$ and $g$ must divide $\sum_{i=0}^{r-1} t_i X^{r-i} + \sum_{i=r}^{63} t_i X^{64-i+r} = U_g$.

Since both polynomials $f$ and $g$ are primitive, they also proved that if $X^k$ divides both $U_f$ and $U_g$ the dimension of the joint kernel will be at least $k$.

Then, if we want a joint distribution of dimension at least $k$, we can build all the polynomials $U_f$ and $U_g$ being divisible by $X^k$ (which greatly reduces the number of such polynomials), and for all polynomials factors $f_i$ of $U_f$ and $g_i$ of $U_g$, check if one pair $(f_i,g_i)$ is primitive and have the proper size.

From the formula given, we already see that if the shift between A and B is $r$ bits, then the maximal degree of the joint distribution will be $r$. In the original cipher, the shifts are uneven (16 and 32) which is why the joint kernel was chosen between A and C which have a maximal shift of 32 bits (it also mean that there are polynomials out there which lead to even bigger join distribution for A and B).

However in our case, the shift either 21, or 42. But it&rsquo;s 64-bit periodic, so a shift of 42 is actually a shift of 22. In this situation, the most we can achieve using two polynomials is 21 bits, and I managed to get polynomials for A and C such that their joint kernel had dimension 21 by using the above method! That is great! However, this is definitely not enought to build any *practical* attack in a ctf.


## Second approach Building backdoors for fun and profit

Now, since the state register is represented in a different order, in order to ensure that the endianness is properly managed, the shifts 21 and 42 actually becomes $64-21=43$ and $64-42=22$ for the rest of this analysis.

Then I figured that such an evenly distributed amount of shifts between A, B and C must lead to a potentially joint distribution between all three polynomials. So I extended the above analysis by considering the shifts for B and for C, leading to the following three polynomials:

-   $\sum_{i=0}^{63} t_i X^{64-i} = U_A$
-   $\sum_{i=0}^{43-1} t_i X^{43-i} + \sum_{i=43}^{63} t_i X^{64-i+43} = U_B$.
-   $\sum_{i=0}^{22-1} t_i X^{22-i} + \sum_{i=22}^{63} t_i X^{64-i+22} = U_C$.

And since the shift between A and B is 21 (remember, 43 and 21 represent the same shift), the triple joint distribution wont be able to go higher than dimension 21.

So let&rsquo;s eliminate the 21 lowest coefficients of all three polynomials $U_A$, $U_B$ and $U_C$ and iterate over all remaining polynomials (there is 2\*\*4 of them) until primitive polynomials of the proper size are found. We quickly find no solution. So we start looking for smaller joint distributions, allowing more coefficients in the three polynomials $U_A, U_B, U_C$ and start over.

No solution is found until we try for dimension 16. Then we found three polynomials

-   $f = X^31 + X^27 + X^26 + X^25 + X^23 + X^17 + X^15 + X^13 + X^11 + X^9 + X^7 + X^6 + X^5 + X^3 + X^2 + X + 1$
-   $g = X^32 + X^30 + X^27 + X^23 + X^18 + X^17 + X^16 + X^12 + X^11 + X^9 + X^8 + X^6 + X^4 + X^3 + X^2 + X + 1$
-   $h = X^33 + X^29 + X^28 + X^27 + X^25 + X^24 + X^23 + X^22 + X^20 + X^19 + X^18 + X^17 + X^9 + X^6 + X^5 + X^4 + X^3 + X + 1$

that have the proper size, are primitive, and the joint kernel distribution of the matrices of the corresponding LFSR initialization have dimension 16.

This means that the entire state space $\mathbb{F}_2^{64}$ can be written as $\mathbb{F}_2^{64}=T+V$ where T is our kernel distribution of dimension 16 and V has dimension 48


## Mount the attack

&ldquo;But wait, 16 is less that 21, your trapdoor is weaker than the original paper! How will it make it easier to attack?&rdquo;

That is correct! However, this time the joint distribution is over all THREE polynomials, meaning that, if we decompose the initial state $s$ as $s=t+v$ where $t\in T$ and $v\in V$, then the initial state of A, B and C (hence the stream output) only depends on $v$, since $T$ is the kernel of all three initialization matrices.

Let&rsquo;s decompose $V=V_1+V_2$ arbitrarily as $V_1$ of dimension 30 and $V_2$ of dimension 18

We are given $2^{18}$ bitstreams, meaning $2^{18}$ different initial state $s$. If we assume that all states are independent, then one of them must have its component in $V2$ equals 0
(the probability of having at least on such element is  $1-\left(1-\frac{1}{2^{18}}\right)^{2^{18}} \sim 0.63$).

Then we can precompute a table with the 64 bits output for all $2^{30}$ state $s$ having a $0$ component in $V2$. This table has size $2^{30}*64= 8 Go$ which is of decent size, and requires $2^{30} computations$ of GEA.

Once this is built once and for all, let&rsquo;s iterate over all $2^{18}$ bitstreams until we find a match between their output and our table. The probability of a random collision is very low on only $2^18$ inputs, since it&rsquo;s a 64 bit output, which mean that a collision is due to the fact that the corresponding $s$ has indeed a zero component in $V_2$ and is purely in $V_1$

Then, since we know (thanks to our table) the corresponding value of $s$ in $V_1$, we know the original value of $s$ after at most $2^{16}$ bruteforce operations. From the right $s$, the proper key is retrieved by clocking or back-clocking the register S with the known corresponding IV until the key is found

The total complexity of the attack is

-   Building a 8Go table with $2^{30}$ GEA1 operations
-   Iterating over $2^{18}$ bistreams and checking if the value is in the table. Using hashmaps would help the process. Since I implemented everything in python in simply used sets.
-   If the value is in the table (which should only happen for a correct bitstream), they key is retrieved with a complexity of $2^{16}$ clocking inversions (which are very simple operations)

which falls under $2^{32}$, right?

![img](./bruteforce.png)


## Theory vs reality, the shame behind the beauty

So, yes, this attack requires about $2^{32}$ iterations, but this requires a lot of optimizations in order to still have a reasonable execution time. The only (very) long process is the table generation, since the remaining part of the script mainly consist in waiting for the bitstreams to be generated (which takes about 10 minutes).

I went for an implementation in python (more specifically, i used pypy to accelerate the computation of the table) and quickly realized that generating $2^{30}$ objects would take a lot of time.
So instead, I reimplemented a faster python version of LFSRs using shifts instead of lists, and added components for letting multiple threads generating a portion of the table in different files (in order to restrict the use of locks and mutex, each thread would manage its own part of the table, which is much easier to implement)

But then, I realized that the generation was still going to be <span class="underline">very</span> long (458h with a CPython interpreter, or 50h with a pypy interpreter). Having 16 threads on my computer, I could have reduced that time down to 3h. Could have run that overnight, but instead, I have to admit that I went for a rather shameful solution:

Instead of splitting $V=V_1+V_2$ with $V_1$ of dimension 30, I decomposed it in $V=V'_1+V'_2$ with $V'_1$ of dimension 26. This means that the table now only has size $2^{26}$ and its generation only takes 30 minutes (in my case, 2 hours, because I only used four threads and went on implementing the rest of my attack).

But, that means that the space $V_2$ now has dimension 22 instead of 18! The probability of having an element equals 0 in at least one of the $2^{18}$ bitstreams drops to  $1-\left(1-\frac{1}{2^{22}}\right)^{2^{18}} \sim 0.06 > 1/17$). You see it coming? Yes, instead of running the attack script once, I ran it 16 times, since that is on average enough to have at least one element in the set. This is simply a complexity tradeoff, my solution with the $2^{18}$ elements would have worked, but taken much longer time. The total runtime of my probabilistic strategy was 3 hours using python on my computer, with only 4 threads. The original strategy would have taken 10h on 4 threads (or 2h30 on 16 threads, but basically would have rendered my computer useless during this time).


<a id="orgda5d5cc"></a>

# Conclusion

This challenge was very interesting, it introduced me to a nice algorithm, reminded me that I shall NEVER use proprietary cryptography, unless thoroughly analyzed by peer reviews, and that backdoor generation is fun :)

Part of me is disappointed to have gone for the &rsquo;cheap trick&rsquo; of requesting 16 connections (it took 1 hour to request the 16 connections on two different threads, and both found the solution, but most of the time comes from the server&rsquo;s generation, the bruteforce part is quite fast), but I known that it would have been possible to do the same with a single packet, by replacing this hour of data generation by longer table generation.

However, in CTFs, time efficiency is sadly sometimes more important that elegance, I figured it would be much longer to implement and debug the extra bruteforce that just re-run the script 16 times in the background until I get an element purely in $V$, and while the computer is running, I could go solving another challenges.



# Appendix


## Source code


### Finding the polynomials

This portion of the code is aggregated sage code

```python
    # from https://eprint.iacr.org/2021/819.pdf
    def getInitMatrix_fast (p , keyLength , shift ):
        P.<x> = PolynomialRing ( GF (2))
        l = p . degree ()
        # Construct transformation matrix A for LFSR in Galois mode
        A = companion_matrix ( x ^ l +1)
        A [0] = list ( p )[0: l ][:: -1]
        A = A . transpose ()
        e0 = vector ( GF (2) ,[1]+[0]*( l -1))
        M = zero_matrix ( GF (2) , l , keyLength )
        for c in range ( keyLength ):
            if ( c < shift ):
                M . set_column (c , A **( shift - c )* e0 )
            else :
                M . set_column (c , A **( keyLength - c + shift )* e0 )
        return M . transpose ()
    
    
    Q = PolynomialRing(GF(2),["X"] + [f"t{i}" for i in range(64)])
    X = Q.gens()[0]
    tis = Q.gens()[1:]
    def build_pols_from_shift(ti,shift):
        p1 = sum([ ti[i]*X**(64-i) for i in range(64)])
        p2 = sum([ti[i]*X**(shift-i) for i in range(shift)]) + sum([ ti[i]*X**(64-i+shift) for i in range(shift,64)])
        return p1, p2
    
    def bad_ts(p1,p2,r3):
        """
        ti that must be deleted to ensure r3 = min(r1,r2)  (see the paper)
        """
        L = set()
        for i in range(r3):
            L.add(p1.coefficient({X:i}))
            L.add(p2.coefficient({X:i}))
        return L
    def update(p1,p2,p3,r3):
        p1b = 0
        p2b = 0
        p3b=0
        to_remove = bad_ts(p1,p2,r3)
        for c in bad_ts(p2,p3,r3):
            to_remove.add(c)
        for i in range(p1.degree()):
            coef = p1.coefficient({X:i})
            if not coef in to_remove:
                p1b += coef*X**i
        for i in range(p2.degree()):
            coef = p2.coefficient({X:i})
            if not coef in to_remove:
                p2b += coef*X**i
        for i in range(p3.degree()):
            coef = p3.coefficient({X:i})
            if not coef in to_remove:
                p3b += coef*X**i
        return p1b,p2b,p3b,64-len(to_remove)+1
    
    p1,p2 = build_pols_from_shift(tis,64-21)
    p1,p3 = build_pols_from_shift(tis,64-42)
    p1,p2,p3,v = update(p1,p2,p3,21) # This is the best we can do that keeps both at degree 64
    
    P.<X> = PolynomialRing(GF(2))
    for b in range(2**19):
    #for b in range(2**16):
        t0,t1,t2,t3,t4,t5,t6,t22,t23,t24,t25,t26,t27,t43,t44,t45,t46,t47,t48  = [(b>>i)&1 for i in range(19)]
        p1 = X^64*t0 + X^63*t1 + X^62*t2 + X^61*t3 + X^60*t4 + X^59*t5 + X^58*t6 + X^42*t22 + X^41*t23 + X^40*t24 + X^39*t25 + X^38*t26 + X^37*t27 + X^21*t43 + X^20*t44 + X^19*t45 + X^18*t46 + X^17*t47 + X^16*t48
        p2 = X^64*t43 + X^63*t44 + X^62*t45 + X^61*t46 + X^60*t47 + X^59*t48 + X^43*t0 + X^42*t1 + X^41*t2 + X^40*t3 + X^39*t4 + X^38*t5 + X^37*t6 + X^21*t22 + X^20*t23 + X^19*t24 + X^18*t25 + X^17*t26 + X^16*t27
        p3 = X^64*t22 + X^63*t23 + X^62*t24 + X^61*t25 + X^60*t26 + X^59*t27 + X^43*t43 + X^42*t44 + X^41*t45 + X^40*t46 + X^39*t47 + X^38*t48 + X^22*t0 + X^21*t1 + X^20*t2 + X^19*t3 + X^18*t4 + X^17*t5 + X^16*t6
        if p1 == 0:
            continue
        for g1 in p1.factor():
            if (( g1[0]. degree ()!= 31 ) or not g1 [0]. is_primitive ()):
                continue
            for g2 in p2.factor():
    
                if (( g2[0]. degree ()!= 32 ) or not g2 [0]. is_primitive ()):
                    continue
                for g3 in p3.factor():
                    if (( g3[0]. degree ()!= 33 ) or not g3 [0]. is_primitive ()):
                        continue
                    print("YAY")
                    print(g1[0])
                    print(g2[0])
                    print(g3[0])
                    M1 = getInitMatrix_fast(g1[0],64,0) # this part here is the code from # from https://eprint.iacr.org/2021/819.pdf
                    M2 = getInitMatrix_fast(g2[0],64,64-21)
                    M3 = getInitMatrix_fast(g3[0],64,64-42)
    
                    T12 = M1 . kernel (). intersection ( M2 . kernel ())
                    T13 = M1 . kernel (). intersection ( M3 . kernel ())
                    T23 = M2 . kernel (). intersection ( M3 . kernel ())
                    T123 = T12.intersection(T13)
                    print("T123 ",T123.dimension() )
                    assert 1==0
    
    inversor64 = zero_matrix(GF(2),64,64)
    for x in range(64):
        inversor64[x,63-x] = 1
    
    inversor31 = zero_matrix(GF(2),31,31)
    for x in range(31):
        inversor31[x,30-x] = 1
    inversor32 = zero_matrix(GF(2),32,32)
    for x in range(32):
        inversor32[x,31-x] = 1
    inversor33 = zero_matrix(GF(2),33,33)
    for x in range(33):
        inversor33[x,32-x] = 1
    
    MA_final = inversor31*M1.transpose()*inversor64
    MB_final = inversor32*M2.transpose()*inversor64
    MC_final = inversor33*M3.transpose()*inversor64
    
    
    K = T123
    V = K.complement()
    V1 = V.subspace(V.basis()[:26])
    V1_basis = V1.basis() # size 26
    V2 = V.subspace(V.basis()[26:])
    V2_basis = V2.basis() # size 22
    K_basis = K.basis()
```    


### Generating the table

```python
    from tqdm import tqdm
    from zlib import crc32 as CRC
    import json
    F = [
        0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1,
        0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1,
        1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1,
        0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1,
        0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1,
        0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0,
        1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1
    ]
    
    
    class LFSR:
        def __init__(self, n, feedback):
            print(len(bin(feedback))-2)
            self.n = n
            self.R = 0  # integer of size 2^n
            self.clk = 0
            self.mask = ((1 << (self.n))-1)
            self.feedback = feedback & self.mask
    
        def set(self, vi):
            self.R = vi
    
        def clock(self, inp=0):
            fb = ((self.R >> (self.n-1)) & 1) ^ inp
            # shift
            self.R <<= 1
            self.R = self.R & self.mask
    
            # feedback
            if fb == 1:
                self.R ^= self.feedback
    
            # clock
            self.clk += 1
    
    
    class MGGA:
        reg_size = [31, 32, 33]
    
        def __init__(self, fb):
            self.A = LFSR(31, fb[0])
            self.B = LFSR(32, fb[1])
            self.C = LFSR(33, fb[2])
    
        def set(self, v1, v2, v3):
            self.A.set(v1)
            self.B.set(v2)
            self.C.set(v3)
    
        def gen(self, bl):
            Z = []
            for i in range(bl):
                # TODO check if this was the issue
                A = [int(b) for b in bin(self.A.R)[2:].zfill(31)][::-1]
                B = [int(b) for b in bin(self.B.R)[2:].zfill(32)][::-1]
                C = [int(b) for b in bin(self.C.R)[2:].zfill(33)][::-1]
                z = F[A[8] | B[4] << 1 | C[0] << 2 | A[9] <<
                      3 | B[2] << 4 | C[32] << 5 | A[23] << 6]
                z ^= F[B[19] | C[2] << 1 | A[17] << 2 | B[30]
                       << 3 | C[13] << 4 | A[28] << 5 | B[26] << 6]
                z ^= F[C[22] | A[30] << 1 | B[31] << 2 | C[29]
                       << 3 | A[5] << 4 | B[10] << 5 | C[28] << 6]
                Z.append(z)
                self.A.clock()
                self.B.clock()
                self.C.clock()
            return Z
    
        def genByte(self):
            Z = self.gen(8)
            return sum(x * 2 ** i for i, x in enumerate(Z)).to_bytes(1, 'little')
    
    
    MAV1 = [
        [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0],
        [1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0],
        [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1],
        [0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1],
        [1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0],
        [1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1],
        [1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1],
        [0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1],
        [1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1],
        [0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0],
        [0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1],
        [1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1],
        [1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1],
        [1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0],
        [1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1],
        [0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0],
        [0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1],
        [1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1],
        [1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0],
        [1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1],
        [1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1],
        [0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1],
        [1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1],
        [1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0],
        [0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0],
        [1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0],
        [1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1],
        [1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0],
        [1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0],
        [1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0],
        [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1],
    ]
    MBV1 = [
        [1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0],
        [1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0],
        [1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0],
        [0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0],
        [0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0],
        [0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1],
        [0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0],
        [1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0],
        [1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0],
        [1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1],
        [0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1],
        [0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1],
        [0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1],
        [0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1],
        [1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0],
        [0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1],
        [1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1],
        [0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0],
        [1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1],
        [0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1],
        [0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1],
        [1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1],
        [1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1],
        [1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0],
        [1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1],
        [0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1],
        [1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0],
        [1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1],
        [1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0],
        [1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0],
        [1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0],
    ]
    MC = [
        [0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1],
        [1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0],
        [1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0],
        [1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0],
        [0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0],
        [0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1],
        [0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1],
        [0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0],
        [1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1],
        [0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0],
        [1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0],
        [0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1],
        [0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
        [0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1],
        [1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0],
        [1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0],
        [0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0],
        [1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1],
        [0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1],
        [1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0],
        [0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1],
        [0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0],
        [0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0],
        [0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1],
        [0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0],
        [1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0],
        [0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0],
        [1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1],
        [0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0],
        [1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0],
        [0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1],
    ]
    
    p1 = 2390928111
    p2 = 5511781215
    p3 = 9594339963
    
    
    def create_table(start, threads):
    
        with open(f"./tmp_{start}_{threads}", "wb") as f:
            M = MGGA([p1, p2, p3])
            for i in tqdm(range(start, 2**26, threads)):
    
                v1 = sum([(sum([MAV1[bit][t]*((i >> t) & 1)
                                for t in range(26)]) & 1) << (bit) for bit in range(31)])
    
                v2 = sum([(sum([MBV1[bit][t]*((i >> t) & 1)
                                for t in range(26)]) & 1) << (bit) for bit in range(32)])
                v3 = sum([(sum([MCV1[bit][t]*((i >> t) & 1)
                                for t in range(26)]) & 1) << (bit) for bit in range(33)])
    
                M.set(v1, v2, v3)
                val = b"".join([M.genByte() for _ in range(8)])
                f.write(val)
    
    
    start = int(input("start = "))
    thread = int(input("thread = "))
    create_table(start, thread)
```    


### Brute force

```python
    import json
    from pwn import *
    from zlib import crc32 as CRC
    from tqdm import tqdm
    from Crypto.Cipher import AES
    from hashlib import sha256
    
    
    def bytes_to_bitlist(bs):
        res = []
        for b in bs:
            for i in range(8):
                res.append((b >> i) & 1)
        return res
    
    
    F = [
        0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1,
        0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1,
        1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1,
        0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1,
        0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1,
        0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0,
        1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1
    ]
    
    K_basis = [
        [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1],
        [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0],
        [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0],
        [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1],
        [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1],
        [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1],
        [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1],
    ]
    
    V1_basis = [
        [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0],
        [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0],
        [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0],
        [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0],
        [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0],
        [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0],
        [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0],
    ]
    
    HOST = "chall.fcsc.fr"
    PORT = 2154
    
    SIZE_TABLE = 2**26
    
    
    class S:
        def __init__(self):
            self.R = 0
            self.clk = 0
    
        def __str__(self):
            return '{:016x}'.format(sum([v * 2 ** i for i, v in enumerate(self.R)]))
    
        def reset(self):
            for i in range(64):
                self.R = 0
    
        def set(self, v):
            self.R = v
    
        def load(self, iv, dir, key):
            IN = []
            IN += bytes_to_bitlist(iv)
            IN += [dir & 1]
            IN += bytes_to_bitlist(key)
            IN += [0] * 128
            for b in IN:
                self.clock(b)
    
        def clock(self, inp):
            b = self.f() ^ inp
            self.R = ((self.R << 1) & 0xffffffffffffffff) | self.R >> 63
            self.R ^= b
            self.clk += 1
    
        def back_clock(self, inp):
            self.R ^= inp
            self.R = (self.R >> 1) | (self.R & 1) << 63
            self.R ^= self.f() << 63
    
            self.clk += 1
    
        def f(self):
            R = [int(i) for i in list(bin(self.R)[2:].zfill(64))][::-1]
            return F[R[60] | R[51] << 1 | R[41] << 2 | R[25] << 3 | R[21] << 4 | R[8] << 5 | R[0] << 6]
    
    
    S0 = S()
    
    
    class Chal():
        def __init__(self, x1: int, x2: int, x3: int):
            self.x1 = x1
            self.x2 = x2
            self.x3 = x3
            pass
    
        def start(self):
    
            self.c = connect(HOST, PORT)
            # self.c = process("./make-gea-great-again.py")
            self.c.sendlineafter(b">>> ", str(self.x1).encode())
            self.c.sendlineafter(b">>> ", str(self.x2).encode())
            self.c.sendlineafter(b">>> ", str(self.x3).encode())
            self.c.recvuntil(b"0x3ff00/0x3ffff")
            r = ""
            while len(r) == 0:
                r = self.c.recvline().decode().strip()
            self.chal = json.loads(r)
            self.c.close()
    
        def build_table(self):
            print("building")
            self.S = set()
            self.T = []
            thread = 4
    
            fd = []
            for i in range(thread):
                fd.append(open(f"./tmp_{i}_{thread}", "rb"))
            for j in tqdm(range(0, SIZE_TABLE*8, 8)):
                for f in (fd):
                    xint = int.from_bytes(f.read(8))
                    self.S.add(xint)
                    # fuck it, j'ai  24Go de ram autant que ça serve
                    self.T.append(xint)
            for f in fd:
                f.close()
    
        def get_indexes(self, x):
            L = []
            if x in self.S:  # O(1) operation
                for i, y in enumerate(self.T):
                    if x == y:
                        L.append(i)
            return L
    
        def bf_kernel_component(self, IV, x_V1):
            IV_L = bytes_to_bitlist(IV)
            S33 = S()
            for b in IV_L:
                S33.clock(b)
            S33.clock(0)  # dir bit
    
            for i in range(2**16):  # size of K
                x_K = [sum([K_basis[t][bit]*((i >> t) & 1)
                           for t in range(16)]) & 1 for bit in range(64)]
                x_candidate = [x_K[bit] ^ x_V1[bit] for bit in range(64)]
    
                k = self.retrieve_secret_from_candidate(S33, x_candidate)
    
                iv = bytes.fromhex(self.chal["flag"]["iv"])
                enc = bytes.fromhex(self.chal["flag"]["enc"])
                E = AES.new(sha256(k).digest(), AES.MODE_CBC, iv=iv)
                dec = E.decrypt(enc)
                if b"FCSC{" in dec and b"}" in dec:
                    print(dec)
                    with open("./flag.txtyeah", "wb") as f:
                        f.write(dec)
                    return True
            return False
    
        def test_solutions(self):
            print("testing")
            for i, out in enumerate(self.chal["data"]):
                IV = i.to_bytes(4, 'little')
                indexes = self.get_indexes(int(out, 16))
    
                if len(indexes) > 0:
                    print("collision potentially found")
                    print(self.chal)
                    with open("./potential_collision.tkt", "w") as f:
                        f.write(json.dumps(self.chal))
    
                for idx in indexes:
                    x_V1 = [sum([V1_basis[t][bit]*((idx >> t) & 1)
                                for t in range(26)]) & 1 for bit in range(64)]
                    if self.bf_kernel_component(IV, x_V1):
                        return True
            return False
    
        def retrieve_secret_from_candidate(self, S33, s):
            S33_bak = S()
            S33_bak.set(S33.R)
    
            state = sum([s[i] << i for i in range(64)])
            S_final = S()
            S_final.set(state)
            for _ in range(128):
                S_final.back_clock(0)
            R97 = S_final.R
    
            key = []
            for i in range(64):
                Ki = S33_bak.f() ^ ((R97 >> (63-i)) & 1) ^ (S33_bak.R >> 63)
                key.append(str(Ki))
                S33_bak.clock(Ki)
    
            return int("".join(key[::-1]), 2).to_bytes(8)[::-1]
    
    
    p1 = 2390928111
    p2 = 5511781215
    p3 = 9594339963
    C = Chal(p1, p2, p3)
    C.build_table()
    pbar = tqdm(256, desc="approximate number of tries with 26-bits table)")
    C.start()
    while not C.test_solutions():
        pbar.update(1)
        C.start()
```    
