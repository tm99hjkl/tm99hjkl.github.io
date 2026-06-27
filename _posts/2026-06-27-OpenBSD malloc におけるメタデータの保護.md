---
layout: post
title:  "OpenBSD malloc におけるメタデータの保護"
---

このポストでは、OpenBSD の [malloc(3)](https://man.openbsd.org/malloc.3) のセキュリティ機構のうち、とくにメタデータの保護について概説する。

メタデータとは malloc が管理するヒープメモリにまつわる様々な情報 (例えば一度割り当てたことのあるメモリが現在 free なのかなど) のことであり、古典的なメモリアロケータでは簡単に改ざんが行えてしまうことが知られている。

# メタデータ

まず保護すべきメタデータの概要を説明する。OpenBSD malloc におけるメタデータの起点は、以下に示す無名共用体の static なグローバルインスタンス `malloc_readonly` である:

```c
/* This object is mapped PROT_READ after initialisation to prevent tampering */
static union {
	struct malloc_readonly mopts;
	u_char _pad[MALLOC_PAGESIZE];
} malloc_readonly __attribute__((aligned(MALLOC_PAGESIZE)))
		__attribute__((section(".openbsd.mutable")));
#define mopts	malloc_readonly.mopts
```

見てのとおりこれはページ境界にアラインするために `_pad` との共用体としているだけで、実質的には `malloc_readonly` 構造体メンバである `mopts` に全てのメタデータが含まれている。malloc はこの `mopts` を取り回しながらヒープメモリを管理している。

`malloc_readonly` 構造体の定義も以下に抜粋する:

```c
struct malloc_readonly {
					/* Main bookkeeping information */
	struct dir_info *malloc_pool[_MALLOC_MUTEXES];
	u_int	malloc_mutexes;		/* how much in actual use? */
	int	malloc_freecheck;	/* Extensive double free check */
	int	malloc_freeunmap;	/* mprotect free pages PROT_NONE? */
	int	def_malloc_junk;	/* junk fill? */
	int	malloc_realloc;		/* always realloc? */
	int	malloc_xmalloc;		/* xmalloc behaviour? */
	u_int	chunk_canaries;		/* use canaries after chunks? */
	int	internal_funcs;		/* use better recallocarray/freezero? */
	u_int	def_maxcache;		/* free pages we cache */
	u_int	junk_loc;		/* variation in location of junk */
	size_t	malloc_guard;		/* use guard pages after allocations? */
#ifdef MALLOC_STATS
	int	malloc_stats;		/* save callers, dump leak report */
	int	malloc_verbose;		/* dump verbose statistics at end */
#define	DO_STATS	mopts.malloc_stats
#else
#define	DO_STATS	0
#endif
	u_int32_t malloc_canary;	/* Matched against ones in pool */
};
```

最も重要なメンバは `malloc_pool` であり、これにはヒープメモリに関するあらゆる情報が含まれている。これ以外のメンバは、基本的にはオプションフラグを表現していると思えばよい。

`malloc_readonly` および `malloc_pool` にはメモリ管理の核となるあらゆる情報が含まれるため、これが意図せず書き換えられることはあってはならない。OpenBSD malloc にはそのような事態を防ぐための様々な機構があり、以下ではそれらを説明する。

# `malloc_readonly` の保護

`malloc_readonly` は、初期化が完了すると `mprotect(.., PROT_READ)` によって直ちに書き込みが禁止される。具体的には、 `_malloc_init` なる初期化関数内で以下のように保護されている:

```c
		if (((uintptr_t)&malloc_readonly & MALLOC_PAGEMASK) == 0) {
			if (mprotect(&malloc_readonly, sizeof(malloc_readonly),
			    PROT_READ))
				wrterror(NULL,
				    "malloc_init mprotect r/o failed");
			if (mimmutable(&malloc_readonly,
			    sizeof(malloc_readonly)))
				wrterror(NULL,
				    "malloc_init mimmutable r/o failed");
		}
```

攻撃者が `mprotect` による保護を破ろうとすると、カーネルがセグメンテーション違反を検知し対象プロセスを強制終了する。これに加え、OpenBSD 固有のシステムコールである `mimmutable` によってこの `mprotect` の設定を変更する (= 書き込み可能に再設定する) ことも禁じられるため、攻撃者が初期化完了後に `malloc_readonly` を書き換えることは実質的に不可能となる。

これに加え、`malloc_readonly` がユーザプログラムから離れた番地に配置されることも保護機構の一助を担っている。

`malloc_readonly` 自体は上で引用したコードのとおり static なグローバル変数であるので、malloc を含むライブラリ (= libc) の `.openbsd.mutable` セクションに配置される。したがって `malloc_readonly` の配置場所は、リンカが libc をリンクするとともに決まる。そして (静的リンクをしない限り) libc がリンクされるアドレスは ASLR によって randomize されるため、プログラムに割り当てられたメモリのどこに `malloc_readonly` が位置するかは推測が困難になっている。

lldb を用いて実際に `main` と `malloc_readonly` と `main` のオフセットが実行毎に異なることを確認してみよう (これは ASLR の動作確認に過ぎないが、簡単であるため実施する) :

```
$ cat a.c
int main(void) { return 0; }
$ cc -lc a.c
$ lldb ./a.out # 1回目
(lldb) b main
(lldb) run
(lldb) p/x (char *)&malloc_readonly - (char *)(void(*)())&main
(long) 0x00000002ad4516b0
$ lldb ./a.out # 2回目
(lldb) b main
(lldb) run
(lldb) p/x (char *)&malloc_readonly - (char *)(void(*)())&main
(long) 0x00000002b29756b0
```

1回目は 0x00000002ad4516b0、2回目は 0x00000002b29756b0 となっており、確かにオフセットが異なっていることが分かる。

このようにして、そもそもユーザプログラムから `malloc_readonly` が配置される領域への侵入を困難にするとともに、侵入された場合においてもカーネルによって対象プログラムを強制終了させることによりこのメタデータを保護している。

# `malloc_pool` の保護

`malloc_pool` はメモリ管理に伴い随時更新され得るため、`malloc_readonly` のようにこのページそのものを `mprotect` することは難しい (不可能ではないが、更新の度に `mprotect` を2度呼び出すことになりパフォーマンスが低下する)。

そこでこれについては、`malloc_pool` 本体を操作するのではなく、その上下にガードページを配置することで書き込み保護を実現している:

```c
		/*
		 * Allocate dir_infos with a guard page on either side. Also
		 * randomise offset inside the page at which the dir_infos
		 * lay (subject to alignment by 1 << MALLOC_MINSHIFT)
		 */
		sz = mopts.malloc_mutexes * sizeof(*d);
		roundup_sz = (sz + MALLOC_PAGEMASK) & ~MALLOC_PAGEMASK;
		if ((p = MMAPNONE(roundup_sz + 2 * MALLOC_PAGESIZE, 0)) ==
		    MAP_FAILED)
			wrterror(NULL, "malloc_init mmap1 failed");
		if (mprotect(p + MALLOC_PAGESIZE, roundup_sz,
		    PROT_READ | PROT_WRITE))
			wrterror(NULL, "malloc_init mprotect1 failed");
		if (mimmutable(p, roundup_sz + 2 * MALLOC_PAGESIZE))
			wrterror(NULL, "malloc_init mimmutable1 failed");
		d_avail = (roundup_sz - sz) >> MALLOC_MINSHIFT;
		d = (struct dir_info *)(p + MALLOC_PAGESIZE +
		    (arc4random_uniform(d_avail) << MALLOC_MINSHIFT));
		STATS_ADD(d[1].malloc_used, roundup_sz + 2 * MALLOC_PAGESIZE);
		for (i = 0; i < mopts.malloc_mutexes; i++)
			mopts.malloc_pool[i] = &d[i];
```

順に詳しく説明する。

まず `(sz + MALLOC_PAGEMASK) & ~MALLOC_PAGEMASK` は `sz` をページサイズの倍数に切り上げている (`(x + y) & ~y` は、`y` が2のべき乗 - 1のとき `x` を `y` の倍数に切り上げるというイディオム)。

次に `MMAPNONE(roundup_sz + 2 * MALLOC_PAGESIZE, 0)` (`mmap(.., PROT_NONE)`  のエイリアス) によって `malloc_pool`  (をページサイズの倍数に切り上げた分) と、`malloc_pool` の上下2ページのガードページ分の mmap 領域を読み書き禁止で割り付け、`malloc_pool` 本体は読み書きを許可するよう再設定し、`mimmutable` で設定をロックしている。

その後 `arc4random_uniform` によって、上で `sz` を切り上げた分だけできた「隙間」を活用し、各 `malloc_pool[i]` をランダムに配置している。この微妙な配置のランダム化は一見無駄にも思えるが、メタデータの位置をピンポイントに把握しなければならない (= 1バイト単位での精度が要求される) 攻撃者に、確かにコストを押し付ける役割を果たしている。

以上により、仮に攻撃者がヒープをオーバーフローさせ運良くこの一連の領域に書き込みを行うことができたとしても、メタデータを掌握することはやはりほぼ不可能となっている。

これに加え `malloc_pool` には更なる保護機構が施されている。`malloc_pool` の構造体である `dir_info` の定義を抜粋してみよう:

```c
struct dir_info {
	u_int32_t canary1;
  // ...
	u_int32_t canary2;
};
```

見て分かるとおり、`dir_info` の上下端にはカナリアが配置されており、オーバーフローにより内部データが侵害されると、以下のように `wrterror` (内部で `abort` を呼び出す) によってプログラムが強制終了される:

```c
	if (mopts.malloc_canary != (d->canary1 ^ (u_int32_t)(uintptr_t)d) ||
	    d->canary1 != ~d->canary2)
		wrterror(d, "internal struct corrupt");
```

また、`canary1` と `canary2` を反転する値として選んでいる点も防御に役立っている。なぜなら、単一の値を埋め尽くすようなオーバーフローによって `canary1` と `canary2` を侵害すると、この二つのカナリアの反転関係が必ず崩れる (`d->canary1 != ~d->canary2` となる) からである。

ここで触れていないものもあるが、様々な機構が折り重なって OpenBSD のメタデータは保護されている。
