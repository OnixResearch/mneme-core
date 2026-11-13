import MnemeKernel
open Aeneas Aeneas.Std Result

/-!
# Byte spans and excerpt windows

Theorems about the generated translation of `crates/mneme-kernel/src/extent.rs`.

Every statement of the form `∃ v, f x = ok v ∧ P v` says that `f x` returns normally (it neither
fails nor diverges) and that the returned value satisfies `P`.
-/

namespace mneme_kernel.extent

/-- A Hoare-style specification names the returned value. -/
private theorem spec_imp_exists {α : Type} {m : Result α} {p : α → Prop}
    (h : WP.spec m p) : ∃ v, m = ok v ∧ p v := by
  cases m with
  | ret r => exact ⟨r, rfl, by simpa using h⟩
  | vis i k => simp at h
  | div => simp at h

private theorem u64_sub_eq {a b : U64} (h : a.val ≤ b.val) :
    ∃ i, b - a = ok i ∧ i.val = b.val - a.val := by
  obtain ⟨i, hi, hv, _⟩ := spec_imp_exists (U64.sub_spec h)
  exact ⟨i, hi, hv⟩

private theorem u64_add_eq {a b : U64} (h : a.val + b.val ≤ U64.max) :
    ∃ i, a + b = ok i ∧ i.val = a.val + b.val :=
  spec_imp_exists (U64.add_spec h)

/-! ## `span_length` -/

private theorem span_length_eval (a b : U64) :
    (b.val < a.val ∧ span_length a b = ok none) ∨
    (a.val ≤ b.val ∧ ∃ n, span_length a b = ok (some n) ∧ n.val = b.val - a.val) := by
  unfold span_length
  by_cases h : b < a
  · have h' := (UScalar.lt_equiv b a).mp h
    left
    simp [h, h']
  · have h' : a.val ≤ b.val := by
      have := (UScalar.lt_equiv b a).not.mp h
      omega
    obtain ⟨i, hi, hv⟩ := u64_sub_eq h'
    right
    refine ⟨h', i, ?_, hv⟩
    simp [h, hi]

/-- `span_length a b` never fails, and it is `some n` exactly when the span runs forwards and
`n` is its length. -/
theorem span_length_some_iff (a b n : U64) :
    ∃ o, span_length a b = ok o ∧
      (o = some n ↔ a.val ≤ b.val ∧ n.val = b.val - a.val) := by
  rcases span_length_eval a b with ⟨hlt, h⟩ | ⟨hle, m, h, hm⟩
  · refine ⟨_, h, ?_⟩
    simp
    omega
  · refine ⟨_, h, ?_⟩
    simp [UScalar.eq_equiv]
    omega

/-- `span_length a b` never fails, and it is `none` exactly when the span runs backwards. -/
theorem span_length_none_iff (a b : U64) :
    ∃ o, span_length a b = ok o ∧ (o = none ↔ b.val < a.val) := by
  rcases span_length_eval a b with ⟨hlt, h⟩ | ⟨hle, m, h, hm⟩
  · exact ⟨_, h, by simp [hlt]⟩
  · refine ⟨_, h, ?_⟩
    simp
    omega

/-! ## `span_in_text` -/

private theorem span_in_text_eq (start stop text_len : U64) :
    span_in_text start stop text_len =
      ok (decide (start.val ≤ stop.val ∧ stop.val ≤ text_len.val)) := by
  unfold span_in_text
  by_cases h : start ≤ stop
  · have h' := (UScalar.le_equiv start stop).mp h
    simp [h, h', UScalar.le_equiv]
  · have h' : ¬ start.val ≤ stop.val := (UScalar.le_equiv start stop).not.mp h
    simp [h, h']

/-- `span_in_text` never fails, and answers `true` exactly when the span lies inside the text. -/
theorem span_in_text_iff (start stop text_len : U64) :
    ∃ v, span_in_text start stop text_len = ok v ∧
      (v = true ↔ start.val ≤ stop.val ∧ stop.val ≤ text_len.val) :=
  ⟨_, span_in_text_eq start stop text_len, by simp⟩

/-! ## `excerpt_window` -/

private theorem excerpt_window_eval (r : ExcerptRequest) :
    (¬ (r.start.val ≤ r.stop.val ∧ r.stop.val ≤ r.text_len.val) ∧ excerpt_window r = ok none) ∨
    (r.start.val ≤ r.stop.val ∧ r.stop.val ≤ r.text_len.val ∧
      r.stop.val - r.start.val ≤ r.max_bytes.val ∧
      excerpt_window r = ok (some { start := r.start, stop := r.stop, truncated := false })) ∨
    (r.start.val ≤ r.stop.val ∧ r.stop.val ≤ r.text_len.val ∧
      r.max_bytes.val < r.stop.val - r.start.val ∧
      ∃ i : U64, i.val = r.start.val + r.max_bytes.val ∧
        excerpt_window r = ok (some { start := r.start, stop := i, truncated := true })) := by
  unfold excerpt_window
  rw [span_in_text_eq]
  simp only [bind_ok]
  by_cases hin : r.start.val ≤ r.stop.val ∧ r.stop.val ≤ r.text_len.val
  · right
    obtain ⟨len, hlen, hlv⟩ := u64_sub_eq hin.1
    simp only [hin, and_self, decide_true, ite_true, hlen, bind_ok, true_and]
    by_cases hle : len ≤ r.max_bytes
    · left
      have hle' := (UScalar.le_equiv len r.max_bytes).mp hle
      simp only [hle, ite_true, and_true]
      omega
    · right
      have hlt : r.max_bytes.val < len.val := by
        have := (UScalar.le_equiv len r.max_bytes).not.mp hle
        omega
      have hbound : r.start.val + r.max_bytes.val ≤ U64.max := by scalar_tac
      obtain ⟨i, hi, hiv⟩ := u64_add_eq hbound
      simp only [hle, ite_false, hi, bind_ok]
      exact ⟨by omega, i, hiv, rfl⟩
  · left
    simp [hin]

/-- `excerpt_window` never fails: in particular `start + max_bytes` cannot overflow on the
truncating branch. -/
theorem excerpt_window_total (r : ExcerptRequest) : ∃ o, excerpt_window r = ok o := by
  rcases excerpt_window_eval r with ⟨_, h⟩ | ⟨_, _, _, h⟩ | ⟨_, _, _, i, _, h⟩
  · exact ⟨_, h⟩
  · exact ⟨_, h⟩
  · exact ⟨_, h⟩

/-- `excerpt_window` never fails, and answers `none` exactly when the span does not lie inside
the text. -/
theorem excerpt_window_none_iff (r : ExcerptRequest) :
    ∃ o, excerpt_window r = ok o ∧
      (o = none ↔ ¬ (r.start.val ≤ r.stop.val ∧ r.stop.val ≤ r.text_len.val)) := by
  rcases excerpt_window_eval r with ⟨hn, h⟩ | ⟨h1, h2, _, h⟩ | ⟨h1, h2, _, i, _, h⟩
  · exact ⟨_, h, by simp [hn]⟩
  · exact ⟨_, h, by simp [h1, h2]⟩
  · exact ⟨_, h, by simp [h1, h2]⟩

/-- Every window returned by `excerpt_window` starts at the cited span, lies inside the span and
the text, is no longer than `max_bytes`, and is marked truncated exactly when the span is longer
than `max_bytes`. An untruncated window is the whole span; a truncated window is exactly the
first `max_bytes` bytes of the span. -/
theorem excerpt_window_spec (r : ExcerptRequest) (w : Window)
    (h : excerpt_window r = ok (some w)) :
    w.start = r.start ∧
    w.start.val ≤ w.stop.val ∧
    w.stop.val ≤ r.stop.val ∧
    w.stop.val ≤ r.text_len.val ∧
    w.stop.val - w.start.val ≤ r.max_bytes.val ∧
    (w.truncated = true ↔ r.max_bytes.val < r.stop.val - r.start.val) ∧
    (w.truncated = false → w.stop = r.stop) ∧
    (w.truncated = true → w.stop.val = r.start.val + r.max_bytes.val) := by
  rcases excerpt_window_eval r with ⟨_, h'⟩ | ⟨h1, h2, h3, h'⟩ | ⟨h1, h2, h3, i, hi, h'⟩
  · rw [h'] at h
    simp at h
  · rw [h'] at h
    simp only [Result.ok.injEq, Option.some.injEq] at h
    subst h
    simp
    omega
  · rw [h'] at h
    simp only [Result.ok.injEq, Option.some.injEq] at h
    subst h
    simp
    omega

/-! ## `is_continuation` -/

/-- A UTF-8 continuation byte: `0b10xxxxxx`, that is `128 ≤ b < 192`. -/
def Continuation (b : U8) : Prop := 128 ≤ b.val ∧ b.val < 192

/-- Masking a byte with `0xC0` gives `0x80` exactly on `128 ≤ n < 192`: checked for every byte,
written as `64 * q + r` with `q < 4` and `r < 64`. -/
private theorem and_192_eq_128_iff (n : Nat) (h : n < 256) :
    (n &&& 192 = 128) ↔ (128 ≤ n ∧ n < 192) := by
  have key : ∀ q < 4, ∀ r < 64,
      ((64 * q + r) &&& 192 = 128) ↔ (128 ≤ 64 * q + r ∧ 64 * q + r < 192) := by
    decide
  have hq : n / 64 < 4 := by omega
  have hr : n % 64 < 64 := by omega
  have hn : 64 * (n / 64) + n % 64 = n := Nat.div_add_mod n 64
  have hkey := key (n / 64) hq (n % 64) hr
  rwa [hn] at hkey

private theorem is_continuation_eq (b : U8) :
    is_continuation b = ok (decide (128 ≤ b.val ∧ b.val < 192)) := by
  unfold is_continuation lift
  simp only [bind_ok]
  have hb : b.val < 256 := by scalar_tac
  have key : (b &&& 192#u8 = 128#u8) ↔ (128 ≤ b.val ∧ b.val < 192) := by
    rw [UScalar.eq_equiv, UScalar.val_and]
    exact and_192_eq_128_iff b.val hb
  simp only [key]

/-- `is_continuation` never fails, and answers `true` exactly on continuation bytes. -/
theorem is_continuation_iff (b : U8) :
    ∃ v, is_continuation b = ok v ∧ (v = true ↔ 128 ≤ b.val ∧ b.val < 192) :=
  ⟨_, is_continuation_eq b, by simp⟩

/-! ## `floor_boundary` -/

private theorem index_usize_eq (s : Slice U8) (i : Usize) (h : i.val < s.val.length) :
    Slice.index_usize s i = ok (s.val[i.val]'h) := by
  obtain ⟨x, hx, hv⟩ := spec_imp_exists (Slice.index_usize_spec s i h)
  rw [hx, hv]

private theorem usize_sub_one_eq {q : Usize} (h : 0 < q.val) :
    ∃ q1, q - 1#usize = ok q1 ∧ q1.val = q.val - 1 := by
  have h1 : (1#usize).val ≤ q.val := by scalar_tac
  obtain ⟨q1, hq1, hv, _⟩ := spec_imp_exists (Usize.sub_spec h1)
  exact ⟨q1, hq1, by scalar_tac⟩

/-- The backwards scan from an in-range position `i`. The invariant is that every byte strictly
above the current position and at or below `i` is a continuation byte; the measure is the
position itself. -/
private theorem floor_boundary_loop_spec (bytes : Slice U8) (i : Usize)
    (hi : i.val < bytes.val.length) :
    floor_boundary_loop bytes i ⦃ p =>
      p.val ≤ i.val ∧
      (p.val = 0 ∨ ∃ b, bytes.val[p.val]? = some b ∧ ¬ Continuation b) ∧
      ∀ j, p.val < j → j ≤ i.val → ∃ b, bytes.val[j]? = some b ∧ Continuation b ⦄ := by
  unfold floor_boundary_loop
  apply loop.spec_decr_nat (fun q : Usize => q.val)
    (fun q => q.val ≤ i.val ∧
      ∀ j, q.val < j → j ≤ i.val → ∃ b, bytes.val[j]? = some b ∧ Continuation b)
  · intro q ⟨hq, hinv⟩
    unfold floor_boundary_loop.body
    by_cases hpos : q > 0#usize
    · have hpos' : 0 < q.val := by scalar_tac
      have hlt : q.val < bytes.val.length := by omega
      simp only [hpos, ↓reduceIte, index_usize_eq bytes q hlt, bind_ok, is_continuation_eq]
      by_cases hc : Continuation bytes.val[q.val]
      · obtain ⟨q1, hq1, hq1v⟩ := usize_sub_one_eq hpos'
        have hc' : 128 ≤ (bytes.val[q.val]).val ∧ (bytes.val[q.val]).val < 192 := hc
        simp only [hc', and_self, decide_true, ↓reduceIte, hq1, bind_ok, WP.spec_ok]
        refine ⟨⟨by omega, ?_⟩, by omega⟩
        intro j hj1 hj2
        by_cases hjq : j = q.val
        · subst hjq
          exact ⟨_, List.getElem?_eq_getElem hlt, hc⟩
        · exact hinv j (by omega) hj2
      · have hc' : ¬ (128 ≤ (bytes.val[q.val]).val ∧ (bytes.val[q.val]).val < 192) := hc
        simp only [hc', decide_false, Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
        exact ⟨hq, Or.inr ⟨_, List.getElem?_eq_getElem hlt, hc⟩, hinv⟩
    · have hz : q.val = 0 := by scalar_tac
      simp only [hpos, ↓reduceIte, WP.spec_ok]
      exact ⟨hq, Or.inl hz, hinv⟩
  · exact ⟨Nat.le_refl _, fun j h1 h2 => by omega⟩

/-- `floor_boundary` never fails and its answer `p` is at most the length. At or past the end
the answer is the length. For an index `i` inside the text the answer is at most `i`, it is `0`
or the byte at `p` is not a continuation byte, and every byte at a position `j` with
`p < j ≤ i` is a continuation byte: `p` is the largest position not above `i` that is `0` or
does not hold a continuation byte. -/
theorem floor_boundary_spec (bytes : Slice U8) (i : Usize) :
    ∃ p, floor_boundary bytes i = ok p ∧
      p.val ≤ bytes.val.length ∧
      (bytes.val.length ≤ i.val → p.val = bytes.val.length) ∧
      (i.val < bytes.val.length →
        p.val ≤ i.val ∧
        (p.val = 0 ∨ ∃ b, bytes.val[p.val]? = some b ∧ ¬ Continuation b) ∧
        ∀ j, p.val < j → j ≤ i.val → ∃ b, bytes.val[j]? = some b ∧ Continuation b) := by
  unfold floor_boundary
  by_cases h : i ≥ Slice.len bytes
  · have h' : bytes.val.length ≤ i.val := by scalar_tac
    refine ⟨Slice.len bytes, ?_, ?_, ?_, ?_⟩
    · simp only [h, ↓reduceIte]
    · simp
    · intro _
      simp
    · intro hlt
      omega
  · have h' : i.val < bytes.val.length := by scalar_tac
    obtain ⟨p, hp, hp1, hp2, hp3⟩ := spec_imp_exists (floor_boundary_loop_spec bytes i h')
    refine ⟨p, ?_, by omega, fun hge => by omega, fun _ => ⟨hp1, hp2, hp3⟩⟩
    simp only [h, ↓reduceIte, hp]

end mneme_kernel.extent
