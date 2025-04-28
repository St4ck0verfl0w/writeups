
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

![img](../src/wu-fcsc-2025/bruteforce .png)


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

