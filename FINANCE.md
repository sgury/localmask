# Finance Mode — מיסוך סכומי כסף / Money-Amount Masking

הרבה ארגונים לא מוכנים שסכומים כספיים — משכורות, מחירים, הכנסות — יגיעו
לספק AI. ‏Finance Mode פותר את זה: **המספרים האמיתיים אף פעם לא עוזבים את
המחשב שלך.** ה-AI רואה ייצוג חלופי, ותשובותיו מתורגמות חזרה למספרים
האמיתיים מקומית, כמו כל טוקן של LocalMask.

Many teams won't paste financial figures into an AI. Finance Mode fixes
that: **the real numbers never leave your machine.** The AI sees a stand-in
representation, and its answers are re-hydrated back to the real figures
locally, like any LocalMask token.

## Enabling

```bash
LOCALMASK_MONEY_MODE=relative localmask scan .
# modes: off (default) | token | bucket | relative
```

Only currency-anchored or finance-keyword-anchored numbers are touched
(`$42,000`, `salary = 95000` — and the same labeled in any pack language: `salariu`, `שכר`, `пароль`-style keywords). Bare numbers —
ports, versions, IDs — are never masked.

## The three modes — and what each one reveals

| Mode | Edition | `$42,000` becomes | The AI can | Revealed to the provider |
|---|---|---|---|---|
| `relative` | **Free / OSS** | `(0.42*R_SALARY)` | compare, sum, compute ratios | relative sizes **within** a category |
| `bucket` | Pro | `~[AMOUNT_5D_USD_0]~` | reason about magnitude | order of magnitude + currency |
| `token` | Pro | `~[AMOUNT_0]~` | nothing numeric | nothing |

The signature `relative` mode is free and open-source. The opacity *choice*
(`token`/`bucket`) is a Pro capability; asking for one on the free edition
fails loudly with an upgrade message — LocalMask never substitutes a
different protection level than the one you chose.

## How `relative` works — honestly

- Each repository gets a **crypto-random base R per category** (salary /
  revenue / price / amount). Every amount is sent as its ratio to R.
- R is generated locally with a CSPRNG and stored in
  `~/.localmask/money_keys.json` with `0600` permissions. **You don't pick
  it and you don't memorize it** — a human-chosen number is guessable; this
  one isn't.
- Separate categories get separate bases, so cross-category ratios (payroll
  as a share of revenue) are hidden too.

**What this is:** key-based relative pseudonymization. Absolute values, the
currency and the scale are hidden — leaking one document elsewhere does not
let anyone reconstruct your numbers without the base stored on your disk.

**What this is not:** encryption of the ratios themselves. Within one
category the AI genuinely sees that Dana earns 1.2× Yossi — that is exactly
the utility you asked it to keep. If even relative sizes are too sensitive,
use `bucket` or `token`.

## When the category can't be identified

An amount with a currency mark but no recognizable category keyword
(`total: $5,000`) still gets a ratio — on the generic `R_AMOUNT` base.
**The protection level is one uniform choice per scan**: in relative mode
everything is relative; nothing silently changes shape based on whether we
recognized a keyword. The honest caveat: uncategorized amounts share the
generic base, so their ratios to each other are visible even if they are
different kinds of money. If that trade-off doesn't fit your data, choose
`bucket` or `token` — for the whole scan.
