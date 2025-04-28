
# Table of Contents

1.  [Introduction](#org0750810)
2.  [A brief description of UOV](#org4df6955)
3.  [Some useful properties](#org9f13b8e)
4.  [The challenge](#orgaaa7df9)
5.  [Conclusion](#orga60a890)
6.  [Appendix](#orgf0006f9)



<a id="org0750810"></a>

# Introduction

This write-up will present a solution for &ldquo;Ca tourne au vinaigre&rdquo;, the second hardest challenge out of 9th cryptographic challenges at of the France CyberSecurity Challenge (FCSC) 2025.

In this challenge is given the source code as well as 1600 signatures using UOV (Unbalanced Oil and Vinegar), and it is required to successfully forge the message &ldquo;Un mauvais vinaigre fait une mauvaise vinaigrette&rdquo;, without the knowledge of the private <span class="underline">and the public key</span>.

As the UOV scheme was completely new to me, I will give a short presentation of the scheme using two different approaches that worked well for me, then proceed to the actual solve of the challenge


<a id="org4df6955"></a>

# A brief description of UOV

The UOV scheme is a scheme using multivariate quadratic equations, which are multivariate polynomials with degree at most two. Its security is based on the assumption that solving a system of quadratic equations in the multivariate case is hard when the number of variable properly exceeds the number of equations

More formally, a quadratic polynomial $f$ can be separated in its monomials of degree 2, 1 and 0 as followed : $f(x) = x^t Q x + L.x + C$ with $Q$ a $n\times n$ matrix, $L$ a row vector of size $n$ and $C$ a constant. Represented as followed, $Q[i,j]$ is the coefficients of the monomial $x_i.x_j$, and $L_i$ is the coefficient of monomial $x_i$.

With theses notations, $Q$ has many representations, as long as the sum of two symmetric coefficient is the same. Usually, Q is represented as an upper triangular matrix:

![img](../src/wu-fcsc-2025/quadratic.png)

which represents the fact that all combinations $x_ix_j$ are possible. For a $n\times n$ matrix, this requires $\frac{n.(n+1)}{2}$ coefficients, and a full quadratic polynomial requires $\frac{(n+1)(n+2)}{2}$ coefficients.

Back to UOV, the public key will then be a system of $o$ quadratic equations $\mathcal{Q}=(\mathcal{Q}_0,...,\mathcal{Q}_{o-1})$, each $\mathcal{Q}_i$ having $n>o$ unknown coefficients, and a signature for the message $t = (t_0,...,t_{o-1})$ will be a valid solution $y=(y_0,...,y_{n-1})$ of the system $\mathcal{Q}(y) = t$. This is a total of $o.\frac{(n+1)(n+2)}{2}$ coefficients.

While this is supposed to be hard, the signer uses the knowledge of a secret mapping $S$ such that each quadratic polynomial equation in $\mathcal{P}=\mathcal{Q}\circ S$ contains only quadratic monomials involving the last $v=n-o$ terms

In this mapping, the quadratic part as an upper triangular matrix looks like this:

![img](../src/wu-fcsc-2025/trapdoor.png)

The square gap at the top left corner indicates that in $x^tQ_i.x$ (the monomials of degree 2), there is no quadratic coefficient $x_i.x_j$ where both $i,j<o$. This essential means, that, by fixing the last $v$ coordinates to any arbitrary value, the resulting system $\mathcal{P}$ is linear in the first $o$ variables. Having exactly $n$ equation gives a much easier system to solve. The resulting system drops to $o\left(\frac{(n+1)(n+2)}{2}-\frac{o(o+1)}{2}\right)$. coefficients

The way the key is generated is as followed:

-   The signer generates a random permutation $S:\mathbb{F}_q^n \mapsto \mathbb{F}_q^n$
-   The signer then generates a random system of equation $\mathcal{P}$ that is only quadratic in the last $v$ variables
-   The public key is the system $\mathcal{Q} = \mathcal{P}\circ S^{-1}$

For a signature of a message $m$, the scheme works as followed

-   Turn $m$ into a vector $t\in\mathbb{F}_q^o$ deterministically
-   Randomly select the $v$ last coefficients $xv = (x_{o},\dots, x_{n-1})$
-   Solve the linear system in $o$ unknown $xo=(x_0,\dots,x_{o-1})$ and equations $\mathcal{P}[\cdot,xv]=t$ and form the vector $x =(xo,xv)\in \mathbb{F}_q^n$
-   Return the point $y=S^{-1}(x)$

At last, the verification of the signature $y$ of a message $m$ is as followed:

-   Turn $m$ into a vector $t\in\mathbb{F}_q^o$ deterministically
-   Verify that $\mathcal{Q}(y) = t$

The upper space of $o$ variables is called the Oil space $\mathcal{O}$ and the lower space of $v$ variables is called the Vinegar space $\mathcal{V}$.

In this write up, I will call these spaces the signer&rsquo;s Oil and Vinegar spaces. This is has nothing to do with private and public elements (the signer&rsquo;s spaces are public, since its the canonical bases). But these spaces are the spaces used for the signature. The difference will be important later.


<a id="org9f13b8e"></a>

# Some useful properties

The following properties are generally true in UOV scheme and will be useful.

-   If $f(x)$ is a multivariate quadratic equation, then $f'(x,y) = f(x+y)-f(x)-f(y)+f(0)$ is a symmetric bilinear form
    -   This can be proved easily using the representation $f(x+y) = (x+y)^tQ(x+y)+L.(x+y) + C$

-   From the signer&rsquo;s perspective, the Oil space is a space where $\mathcal{P}$ is linear. This can be extended to the public key equations: $\mathcal{O}' = S^{-1}(\mathcal{O})$ is a space where the $\mathcal{Q}$ is linear (since the quadratic part disappear in the signer&rsquo;s Oil space, and won&rsquo;t come back when you go back to the verifier&rsquo;s space ). Hence the spaces $\mathcal{O'}$ and $\mathcal{V'}=S^{-1}(\mathcal{V})$ will be called the forger&rsquo;s Oil and Vinegar space. These are privates, because they require the secret mapping $S$, but are important to retrieve for the forgery.

Now we have everything we need to tackle the challenge


<a id="orgaaa7df9"></a>

# The challenge

This challenge is decomposed in two parts. Understanding the vulnerability is straightforward, but retrieving the public key (or an equivalent key) is quite difficult.

In this challenge $o = 24$, $v=36$ and $n=o+v=60$


## The vulnerability

By investing the source code, there are two parts that can be considered suspicious:

-   There is a typo in the system generation. While the square gap part is supposed to have the size of the signer&rsquo;s Oil space, it actually is larger. This means that the signer&rsquo;s Oil space is in practice bigger that it should. This has various implication (that this writeup is too narrow to contain), but in our case it reduces the number of unknown coefficients in the resulting <span class="underline">private</span> key. This was not used in the end, but it could have helped retrieving a public key in the second part using much less signatures (provided all the systems still had solutions).

-   Much worst, the vinegar part $xv$ is deterministically from the message! This means that for all 1600 messages, we are able to get the signer&rsquo;s Vinegar vector. Since $\mathcal{V}'=S^{-1}\mathcal{V}$ is linear, only 36\*60 equations are required to find the forger&rsquo;s Vinegar space by interpolation. Lets call $S_v$ the restriction of $S$ to $\mathcal{V'}$. Note that both spaces have the same dimension 36, so $S_v$ is indeed a bijection.

If we want to decompose $y=yv+yo$ with $yv\in\mathcal{V'}$ and $yo\in\mathcal{O}'$ for a signature $y$ with $S(y)$ matching the deterministically generated known $xv$, we find that $yv=S_v^{-1}(x_v)$ hence $yo = y-yv$.

This means that for all 1600 signatures, we have found corresponding decomposition in the forgers vinegar and oil space, more than enough to build a basis of each. And as we have seen, solving the public system is trivial when we have a vector in the forger&rsquo;s vinegar space.


## Retrieving the public key

![img](../src/wu-fcsc-2025/meme_pubkey.jpg)

Another implicit yet very important condition to solving the public system is, well, having the public system. Unfortunately, we don&rsquo;t have it.

UOV is among thoses scheme where enough signature allow you to retrieve the public key, this is very simple using basic interpolation.

The private system have $o\left(\frac{(n+1)(n+2)}{2}-\frac{o(o+1)}{2}\right)=38,184$ coefficients at most and we have $1600*o= 38,400$ equations. This could have been interpolated, but we only have the $xv$ not the $xo$ (we only computed the mapping $S$ on the vinegar space).

For the record, I generated an instance of the problem an verified that the number of equations is indeed lower that it should, since the private matrix is more sparse. It would be anticipated
$o\left(\frac{(n+1)(n+2)}{2}-\frac{\textbf{v}(\textbf{v}+1)}{2}\right)=29,400$ coefficients at most, and we get :

    sum([Vinaigrette.secret_system[i].number_of_terms() for i in range(24)])

    29279

Considering the public part (that can be interpolated), the system has $o\left(\frac{(n+1)(n+2)}{2}\right)=45'384$ coefficients at most, and indeed we get

    sum([Vinaigrette.public_system[i].number_of_terms() for i in range(24)])

    45218

This is too much unknowns to be interpolated. It could have been with 1,900 signatures, but I guess the chalmakers wanted to see the challenge going for a bit longer.

Fair enough, let&rsquo;s not blindy try and interpolate $\mathcal{Q}$ entirely, but exploit the fact that we known the forger&rsquo;s vinegar and oil spaces, as well as $yv$.
From our initial bilinearization, we have

$$t=\mathcal{Q}(y)=\mathcal{Q}(yv+yo)=\mathcal{Q}(yv)+\mathcal{Q}(yo)-\mathcal{Q'}(yv,yo)-Q(0)$$

With the first term quadratic in $yv$, the second is linear in $yo$ (it&rsquo;s an element of the signer&rsquo;s oil space) and the third bilinear. If we think blindy about interpolation of matrix and polynomials, we have not really changed the number of unknowns, right? But thinking in term of dimensions, we realised that the equation is much shorter.
Let&rsquo;s look at the first term $\mathcal{Q}(yv)$. It is quadratic on a vector $yv$ with $60$ coefficients, so it should require $61*62/2=1891$ monomials per equation. But in fact $yv$ lies in $\mathcal{V'}$ of dimension $v=36$ that is <span class="underline">fully known</span>. This means that in fact $\mathcal{Q}(yv)$ involves only $\frac{(v+1)(v+2)}{2}=703$ monomials per equation, not in the coefficients of $yv$ (there are still 60 of them) but in the decomposition of $yv$ in $\mathcal{V'}$ called $zv$ which only requires $v=36$ coefficients. If we do similarly for $yo$, it can be written in a more compact representation of $o=24$ vectors in any basis of $\mathcal{O'}$, hence the linear segment $\mathcal{Q}(yo)$ truly involves only $o+1=25$ coefficients per equation instead of $61$. This is nice, but the biggest change is the symmetric bilinear map $\mathcal{Q'}(yo,yv)$ which would initially require $60*60=3600$ coefficients and now requires $o*v =864$ coefficients.

In total, this new mapping leads to $703+25+864+1=1,592$ monomials per equation. In fact, we have not taken into account that the coefficient constant in $\mathcal{Q}(yv)$ and $\mathcal{Q}(yo)$ is the same, which means that there should be one less unknown, for a total of $38'184$ coefficient to interpolate.

What do you know? We got exactly the number of coefficients we would have if we had interpolated the public system $\mathcal{P}$, well done!


## Finishing the challenge

From the system we got, we can compute the deterministic vinegar part $xv$ just like the signer would have done, move it to $yv$ then $zv$ using our known mapping, then easily solve the interpolated system which is linear in $zo$, retrieve $yo$ from $zo$ and finally get the signature  $y=yo+yv$

The whole script runs for less that 5 minutes


<a id="orga60a890"></a>

# Conclusion

This challenge was really interesting for many reason. First, it got me hooked into a nice signature scheme with elegant trapdoor just as we like them (for some reason, it reminded me of the Knapsack Problem signature scheme), that i never actually got a chance to look at. This scheme can be represented with matrices, polynomials and vector spaces, a very nice reminder that objects in algebra are often alike.


<a id="orgf0006f9"></a>

# Appendix


## Why we might have required less signature

![img](../src/wu-fcsc-2025/meme_oil.jpg)

As explained the typo in the key generation means that the number of coefficients in the public system is $29,400$. This mean that, using the same strategy, we could have extended the signer&rsquo;s and forger&rsquo;s Oil spaces while reducing the signer&rsquo;s and forger&rsquo;s Vinegar spaces, and do the same attack with $v=24$ and $o=36$

The final number of coefficients would match $29,400$, and only $1,300$ signatures would in fact be required. I believe there will still be some difficulties, since we wont get enough equations (If the Oil space have size 36, then there should be 36 equations, not 24). Plus, we would miss 12 bytes of the signature enforced by shake256. But i still find interesting that, theoretically speaking, less signatures are required for interpolation.

## Source code

Here is the source code in sage. I aggregated multiple sage cells together depending on what they were used to do


### constants

```python
    import json
    from Crypto.Hash import SHAKE256
    tot = 60
    v_size = 36 # could be 24
    intend_o_size = 24
    intend_v_size = 36
    o_size = tot-v_size
    F = GF(256)
    def bytes_to_vec(b):
        return vector(F, [F.from_integer(k) for k in b])
    with open('./output.txt') as f:
        data = json.load(f)
```

### Retrieve $S_v$

```python
    # find set of yi with full rank
    full_rank_list = []
    list_of_y=[]
    for t,y in  list(data.items()):
        y = bytes_to_vec(bytes.fromhex(y))
        if len(list_of_y) == 0:
            full_rank_list.append((t,y))
            list_of_y.append(y)
            continue
        M = Matrix(F,list_of_y+ [y])
        if M.rank() == len(list_of_y)+1:
            full_rank_list.append((t,y))
            list_of_y.append(y)
        if len(list_of_y)==tot:
            break
    
    # Find mapping Sv
    M = Matrix(F,v_size*tot,v_size*tot)
    B = vector(F,v_size*tot)
    for k,(t,y) in enumerate(full_rank_list):
        message = bytes.fromhex(t)
        shake = SHAKE256.new()
        shake.update(message)
        _ = shake.read(intend_o_size) # shake must be correct
    
        # Vinegar values
        v_values = list(bytes_to_vec(shake.read(intend_v_size)))[:v_size]
        for i in range(v_size): # i is the ith element of x_v (known by shake)
            # hence, writing at row v_size*k+i
            for j in range(tot):
                M[v_size*k+i,tot*i+j] = y[j]
            B[v_size*k+i] = v_values[i]
    
    
    
    Sv_unstruct = M.inverse()*B  #coefficients of mapping in wrong order
    Sv = Matrix(F,v_size,tot)
    for i in range(v_size):
        for j in range(tot):
            Sv[i,j] = Sv_unstruct[tot*i+j]
    c = 0
    for t,y in  list(data.items()):
        c += 1
        message = bytes.fromhex(t)
        shake = SHAKE256.new()
        shake.update(message)
        _ = shake.read(24) # shake must be correct
        assert Sv*bytes_to_vec(bytes.fromhex(y)) == bytes_to_vec(shake.read(intend_v_size))[:v_size]
    print(c)
```

### Compute forger&rsquo;s Oil and vinegar space

```python
    Ys = []
    from tqdm import tqdm
    for t,y in  tqdm(list(data.items())):
        message = bytes.fromhex(t)
        shake = SHAKE256.new()
        shake.update(message)
        hash_m = shake.read(intend_o_size) # shake must be correct
        yv = Sv.solve_right(bytes_to_vec(shake.read(intend_v_size))[:v_size])
        yo = bytes_to_vec(bytes.fromhex(y)) - yv
        t_vec = bytes_to_vec(hash_m)
        Ys.append((yo,yv,t_vec))
    O_space = []
    for yo,_,_ in Ys[:tot]:
        O_space.append(yo)
    O_for_y = Matrix(O_space).image() # use the yo to build O_for_y
    print(O_for_y)
    O_y_basis = O_for_y.basis()
    
    V_space = []
    for _,yv,_ in Ys[:60]:
        V_space.append(yv)
    V_for_y = Matrix(V_space).image() # use the yv to build V_for_y
    V_y_basis = V_for_y.basis()
    print(V_for_y)

```

### Compute arbitrary zv and zo and solve the system

```python
    fv = Matrix(V_y_basis).pseudoinverse()
    fo = Matrix(O_y_basis).pseudoinverse()
    system = []
    for yo,yv,t in Ys:
        zo = fo.solve_right(yo)
        zv = fv.solve_right(yv)
        system.append((zo,zv,yo,yv,t))
    # now lets build the system of equations
    #let's interpolate one eq at a time, better for
    unknown = o_size*v_size + v_size*(v_size+1)//2 + tot +1
    print(unknown)
    systems = []
    for LINE in tqdm(range(intend_o_size)):
        M = Matrix(GF(256),len(system),unknown)
        B = vector(GF(256),len(system))
        for i,(zo,zv,yo,yv,t) in enumerate(system):
            assert (Sv*yo).is_zero()
            assert yv in V_for_y
            assert yo == fo*zo
            assert yv == fv*zv
            total_eqs = 0
    
            # quadratic portion (Qofv)(Zv)
            for j in range(v_size):
                for k in range(j,v_size):
                    M[i,total_eqs] = zv[j]*zv[k]
                    total_eqs+=1
    
            # linear part of (Qofv)(Zv)
            for j in range(o_size):
                M[i,total_eqs] = (zo)[j]
                total_eqs+=1
    
            for j in range(v_size):
                M[i,total_eqs] = (zv)[j]
                total_eqs+=1
            # biquadratic sectoin (fv o Q' o fo)(zv,zo)
            for j in range(v_size):
                for k in range(o_size):
                    M[i,total_eqs] = zv[j]*zo[k]
                    total_eqs += 1
    
            M[i,total_eqs] = 1 # constant term
            total_eqs += 1
            B[i] = t[LINE]
        systems.append(M.solve_right(B))
```

### forge the message

```python
    message_to_forge = b"Un mauvais vinaigre fait une mauvaise vinaigrette!"
    
    shake = SHAKE256.new()
    shake.update(message_to_forge)
    # Target values
    hash_values = bytes_to_vec(shake.read(intend_o_size))
    # Vinegar values
    v_values = bytes_to_vec(shake.read(intend_v_size))
    yv = Sv.solve_right(v_values)
    zv = fv.solve_right(yv)
    P = PolynomialRing(F,[f"zo{i}" for i in range(o_size)])
    zo = P.gens()
    Eqs  = []
    for line in tqdm(range(intend_o_size)):
        sum_pols = 0
        total_eqs = 0
    
        # quadratic portion (Qofv)(Zv)
        for j in range(v_size):
            for k in range(j,v_size):
                sum_pols += systems[line][total_eqs] * zv[j]*zv[k]
                total_eqs+=1
    
        # linear part of (Qofv)(Zv)
        for j in range(o_size):
            sum_pols += systems[line][total_eqs] * zo[j]
            total_eqs+=1
    
        for j in range(v_size):
            sum_pols += systems[line][total_eqs] * zv[j]
            total_eqs+=1
    
        # biquadratic sectoin (fv o Q' o fo)(zv,zo)
        for j in range(v_size):
            for k in range(o_size):
                sum_pols += systems[line][total_eqs] * zv[j] * zo[k]
                total_eqs+=1
    
        sum_pols += systems[line][total_eqs] # constant term
        total_eqs += 1
    
        sum_pols -=hash_values[line]
        Eqs.append(sum_pols)
    
    I =Ideal(Eqs)
    solve = I.variety()[0]
    
    
    zo_y = vector(F,[solve[u] for u in zo])
    yo = fo*zo_y
    y = yo+yv
    def vec_to_bytes(vec):
        return bytes([k.to_integer() for k in vec])
    flag_signature = vec_to_bytes(y)
    flag = f"FCSC{{{flag_signature.hex()}}}"
    print(flag)
```
