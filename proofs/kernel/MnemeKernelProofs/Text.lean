import MnemeKernel
open Aeneas Aeneas.Std Result

/-!
# Byte-level syntax checks

Theorems about the generated translation of `crates/mneme-kernel/src/text.rs`.

Every statement of the form `∃ v, f x = ok v ∧ P v` says that `f x` returns normally (it neither
fails nor diverges) and that the returned value satisfies `P`.
-/

namespace mneme_kernel.text

/-- A Hoare-style specification names the returned value. -/
private theorem spec_imp_exists {α : Type} {m : Result α} {p : α → Prop}
    (h : WP.spec m p) : ∃ v, m = ok v ∧ p v := by
  cases m with
  | ret r => exact ⟨r, rfl, by simpa using h⟩
  | vis i k => simp at h
  | div => simp at h

private theorem index_usize_eq (s : Slice U8) (i : Usize) (h : i.val < s.val.length) :
    Slice.index_usize s i = ok (s.val[i.val]'h) := by
  obtain ⟨x, hx, hv⟩ := spec_imp_exists (Slice.index_usize_spec s i h)
  rw [hx, hv]

/-- An index below the length of a slice can be incremented without overflow. -/
private theorem usize_add_one_eq (s : Slice U8) {i : Usize} (h : i.val < s.val.length) :
    ∃ j, i + 1#usize = ok j ∧ j.val = i.val + 1 := by
  have hb : i.val + (1#usize).val ≤ Usize.max := by scalar_tac
  obtain ⟨j, hj, hv⟩ := spec_imp_exists (Usize.add_spec hb)
  exact ⟨j, hj, by scalar_tac⟩

/-! ## Byte classes -/

/-- A lowercase hexadecimal digit: `0` to `9` or `a` to `f`. -/
def LowerHex (b : U8) : Prop := (48 ≤ b.val ∧ b.val ≤ 57) ∨ (97 ≤ b.val ∧ b.val ≤ 102)

/-- A byte that may start an unquoted atom: `a` to `z`. -/
def AtomStart (b : U8) : Prop := 97 ≤ b.val ∧ b.val ≤ 122

/-- A byte that may continue an unquoted atom: `a` to `z`, `A` to `Z`, `0` to `9` or `_`. -/
def AtomContinue (b : U8) : Prop :=
  (97 ≤ b.val ∧ b.val ≤ 122) ∨ (65 ≤ b.val ∧ b.val ≤ 90) ∨ (48 ≤ b.val ∧ b.val ≤ 57) ∨
    b.val = 95

instance (b : U8) : Decidable (LowerHex b) := by unfold LowerHex; infer_instance
instance (b : U8) : Decidable (AtomStart b) := by unfold AtomStart; infer_instance
instance (b : U8) : Decidable (AtomContinue b) := by unfold AtomContinue; infer_instance

private theorem is_lower_hex_byte_eq (b : U8) :
    is_lower_hex_byte b = ok (decide (LowerHex b)) := by
  unfold is_lower_hex_byte LowerHex
  simp only [ge_iff_le, UScalar.le_equiv, UScalar.ofNatCore_val_eq]
  split_ifs <;>
    simp only [Result.ok.injEq, decide_eq_decide, true_eq_decide_iff, false_eq_decide_iff] <;>
    omega

/-- `is_lower_hex_byte` never fails, and answers `true` exactly on lowercase hex digits. -/
theorem is_lower_hex_byte_iff (b : U8) :
    ∃ v, is_lower_hex_byte b = ok v ∧ (v = true ↔ LowerHex b) :=
  ⟨_, is_lower_hex_byte_eq b, by simp⟩

private theorem is_atom_start_eq (b : U8) : is_atom_start b = ok (decide (AtomStart b)) := by
  unfold is_atom_start AtomStart
  simp only [ge_iff_le, UScalar.le_equiv, UScalar.ofNatCore_val_eq]
  split_ifs <;>
    simp only [Result.ok.injEq, decide_eq_decide, false_eq_decide_iff] <;>
    omega

/-- `is_atom_start` never fails, and answers `true` exactly on lowercase ASCII letters. -/
theorem is_atom_start_iff (b : U8) :
    ∃ v, is_atom_start b = ok v ∧ (v = true ↔ AtomStart b) :=
  ⟨_, is_atom_start_eq b, by simp⟩

private theorem is_atom_continue_eq (b : U8) :
    is_atom_continue b = ok (decide (AtomContinue b)) := by
  unfold is_atom_continue AtomContinue
  simp only [ge_iff_le, UScalar.le_equiv, UScalar.eq_equiv, UScalar.ofNatCore_val_eq]
  split_ifs <;>
    simp only [Result.ok.injEq, decide_eq_decide, true_eq_decide_iff] <;>
    omega

/-- `is_atom_continue` never fails, and answers `true` exactly on ASCII letters, digits and
underscores. -/
theorem is_atom_continue_iff (b : U8) :
    ∃ v, is_atom_continue b = ok v ∧ (v = true ↔ AtomContinue b) :=
  ⟨_, is_atom_continue_eq b, by simp⟩

/-! ## `is_lower_hex` -/

/-- The scan from any state. The invariant is that the verdict on the whole slice, computed from
the current flag and the bytes not read yet, never changes; the measure is the number of bytes
not read yet. -/
private theorem is_lower_hex_loop_spec (s : Slice U8) (valid : Bool) (index : Usize)
    (hindex : index.val ≤ s.val.length) :
    is_lower_hex_loop s valid index ⦃ r =>
      r = (valid && (s.val.drop index.val).all (fun b => decide (LowerHex b))) ⦄ := by
  unfold is_lower_hex_loop
  apply loop.spec_decr_nat
    (fun (x : Bool × Usize) => s.val.length - x.2.val)
    (fun (x : Bool × Usize) => x.2.val ≤ s.val.length ∧
      (x.1 && (s.val.drop x.2.val).all (fun b => decide (LowerHex b))) =
        (valid && (s.val.drop index.val).all (fun b => decide (LowerHex b))))
  · rintro ⟨v, i⟩ ⟨hi, hinv⟩
    simp only at hi hinv ⊢
    unfold is_lower_hex_loop.body
    by_cases hlt : i < Slice.len s
    · have hlt' : i.val < s.val.length := by scalar_tac
      cases v with
      | true =>
        obtain ⟨j, hj, hjv⟩ := usize_add_one_eq s hlt'
        simp only [hlt, ↓reduceIte, index_usize_eq s i hlt', bind_ok, is_lower_hex_byte_eq, hj,
          WP.spec_ok]
        refine ⟨⟨by omega, ?_⟩, by omega⟩
        rw [← hinv, hjv, List.drop_eq_getElem_cons hlt']
        simp only [List.all_cons, Bool.true_and]
      | false =>
        simp only [hlt, ↓reduceIte, Bool.false_eq_true, WP.spec_ok]
        simpa using hinv
    · have hge : i.val = s.val.length := by scalar_tac
      simp only [hlt, ↓reduceIte, WP.spec_ok]
      rw [← hinv, hge]
      simp
  · exact ⟨hindex, rfl⟩

private theorem is_lower_hex_eq (s : Slice U8) :
    is_lower_hex s = ok (s.val.all (fun b => decide (LowerHex b))) := by
  obtain ⟨r, hr, hv⟩ := spec_imp_exists (is_lower_hex_loop_spec s true 0#usize (by simp))
  unfold is_lower_hex
  rw [hr, hv]
  simp

/-- `is_lower_hex` never fails, and answers `true` exactly when every byte is a lowercase hex
digit. -/
theorem is_lower_hex_iff (s : Slice U8) :
    ∃ v, is_lower_hex s = ok v ∧ (v = true ↔ ∀ b ∈ s.val, LowerHex b) :=
  ⟨_, is_lower_hex_eq s, by simp⟩

/-! ## `is_safe_atom` -/

/-- The scan from any state, with the same invariant and measure as `is_lower_hex_loop_spec`. -/
private theorem is_safe_atom_loop_spec (s : Slice U8) (safe : Bool) (index : Usize)
    (hindex : index.val ≤ s.val.length) :
    is_safe_atom_loop s safe index ⦃ r =>
      r = (safe && (s.val.drop index.val).all (fun b => decide (AtomContinue b))) ⦄ := by
  unfold is_safe_atom_loop
  apply loop.spec_decr_nat
    (fun (x : Bool × Usize) => s.val.length - x.2.val)
    (fun (x : Bool × Usize) => x.2.val ≤ s.val.length ∧
      (x.1 && (s.val.drop x.2.val).all (fun b => decide (AtomContinue b))) =
        (safe && (s.val.drop index.val).all (fun b => decide (AtomContinue b))))
  · rintro ⟨v, i⟩ ⟨hi, hinv⟩
    simp only at hi hinv ⊢
    unfold is_safe_atom_loop.body
    by_cases hlt : i < Slice.len s
    · have hlt' : i.val < s.val.length := by scalar_tac
      cases v with
      | true =>
        obtain ⟨j, hj, hjv⟩ := usize_add_one_eq s hlt'
        simp only [hlt, ↓reduceIte, index_usize_eq s i hlt', bind_ok, is_atom_continue_eq, hj,
          WP.spec_ok]
        refine ⟨⟨by omega, ?_⟩, by omega⟩
        rw [← hinv, hjv, List.drop_eq_getElem_cons hlt']
        simp only [List.all_cons, Bool.true_and]
      | false =>
        simp only [hlt, ↓reduceIte, Bool.false_eq_true, WP.spec_ok]
        simpa using hinv
    · have hge : i.val = s.val.length := by scalar_tac
      simp only [hlt, ↓reduceIte, WP.spec_ok]
      rw [← hinv, hge]
      simp
  · exact ⟨hindex, rfl⟩

/-- The verdict on a byte list: a lowercase ASCII letter followed by ASCII letters, digits and
underscores. -/
private def safeAtomSpec : List U8 → Bool
  | [] => false
  | first :: rest => decide (AtomStart first) && rest.all (fun b => decide (AtomContinue b))

private theorem is_safe_atom_eq (s : Slice U8) : is_safe_atom s = ok (safeAtomSpec s.val) := by
  unfold is_safe_atom
  cases hl : s.val with
  | nil =>
    simp [hl, safeAtomSpec]
  | cons first rest =>
    have h0 : (0#usize).val < s.val.length := by simp [hl]
    have hfirst : s.val[(0#usize).val]'h0 = first := by simp [hl]
    obtain ⟨r, hr, hv⟩ :=
      spec_imp_exists (is_safe_atom_loop_spec s true 1#usize (by simp [hl]))
    have hne : ¬ (s.val.length = 0) := by simp [hl]
    have hdrop : List.drop (1#usize).val s.val = rest := by simp [hl]
    rw [hdrop] at hv
    simp only [core.slice.Slice.is_empty, Slice.length, hne, decide_false, bind_ok,
      Bool.false_eq_true, ↓reduceIte, index_usize_eq s 0#usize h0, hfirst, is_atom_start_eq, hr,
      hv, safeAtomSpec]
    cases decide (AtomStart first) <;> simp

/-- `is_safe_atom` never fails, and answers `true` exactly on a lowercase ASCII letter followed
by ASCII letters, digits and underscores. -/
theorem is_safe_atom_iff (s : Slice U8) :
    ∃ v, is_safe_atom s = ok v ∧
      (v = true ↔
        ∃ first rest, s.val = first :: rest ∧ AtomStart first ∧ ∀ b ∈ rest, AtomContinue b) := by
  refine ⟨_, is_safe_atom_eq s, ?_⟩
  cases s.val with
  | nil => simp [safeAtomSpec]
  | cons first rest => simp [safeAtomSpec]

/-- A safe atom is not empty. -/
theorem is_safe_atom_not_empty (s : Slice U8) (h : is_safe_atom s = ok true) : s.val ≠ [] := by
  rw [is_safe_atom_eq] at h
  intro hnil
  simp [hnil, safeAtomSpec] at h

/-- Every byte of a safe atom is an ASCII letter, a digit or an underscore, so the text contains
no parenthesis, comma, period, quote, space or other punctuation. -/
theorem is_safe_atom_alphanumeric (s : Slice U8) (h : is_safe_atom s = ok true) :
    ∀ b ∈ s.val, AtomContinue b := by
  rw [is_safe_atom_eq] at h
  cases hl : s.val with
  | nil => simp
  | cons first rest =>
    simp only [hl, safeAtomSpec, Result.ok.injEq, Bool.and_eq_true, decide_eq_true_eq,
      List.all_eq_true] at h
    intro b hb
    rcases List.mem_cons.mp hb with rfl | hb
    · exact Or.inl h.1
    · exact h.2 b hb

/-- A safe atom starts with a lowercase ASCII letter, so it cannot be read as a variable. -/
theorem is_safe_atom_not_variable (s : Slice U8) (h : is_safe_atom s = ok true) :
    ∃ first, s.val.head? = some first ∧ AtomStart first := by
  rw [is_safe_atom_eq] at h
  cases hl : s.val with
  | nil => simp [hl, safeAtomSpec] at h
  | cons first rest =>
    simp only [hl, safeAtomSpec, Result.ok.injEq, Bool.and_eq_true, decide_eq_true_eq] at h
    exact ⟨first, rfl, h.1⟩

/-! ## `segment_ok` -/

private theorem segment_ok_eq (len : U8) (dots : Bool) :
    segment_ok len dots = ok (decide (0 < len.val ∧ ¬ (dots = true ∧ len.val ≤ 2))) := by
  unfold segment_ok
  simp only [gt_iff_lt, UScalar.lt_equiv, UScalar.le_equiv, UScalar.ofNatCore_val_eq]
  by_cases hpos : 0 < len.val
  · cases dots
    · simp [hpos]
    · by_cases h2 : len.val ≤ 2 <;> simp [hpos, h2]
  · simp [hpos]

/-- `segment_ok` never fails, and accepts a finished segment exactly when it is not empty and is
not one or two periods. -/
theorem segment_ok_iff (len : U8) (dots : Bool) :
    ∃ v, segment_ok len dots = ok v ∧
      (v = true ↔ 0 < len.val ∧ ¬ (dots = true ∧ len.val ≤ 2)) :=
  ⟨_, segment_ok_eq len dots, by cases dots <;> simp⟩

/-! ## `path_step` -/

/-- `path_step` never fails. A NUL (0) or a backslash (92) invalidates the scan and changes
nothing else. A slash (47) closes the current segment: the scan stays valid only if it was valid
and the segment is acceptable, and a new empty segment starts. Any other byte extends the current
segment: its length counter grows but saturates at three, and it stays all-periods only if the
byte is a period (46). -/
theorem path_step_spec (scan : PathScan) (b : U8) :
    ∃ next, path_step scan b = ok next ∧
      (b.val = 0 ∨ b.val = 92 →
        next.valid = false ∧ next.segment_len = scan.segment_len ∧
          next.only_dots = scan.only_dots) ∧
      (b.val = 47 →
        next.valid = (scan.valid && decide (0 < scan.segment_len.val ∧
          ¬ (scan.only_dots = true ∧ scan.segment_len.val ≤ 2))) ∧
        next.segment_len.val = 0 ∧ next.only_dots = true) ∧
      (b.val ≠ 0 → b.val ≠ 92 → b.val ≠ 47 →
        next.valid = scan.valid ∧
        next.segment_len.val = min 3 (scan.segment_len.val + 1) ∧
        next.only_dots = (scan.only_dots && decide (b.val = 46))) := by
  unfold path_step
  simp only [UScalar.eq_equiv, UScalar.lt_equiv, UScalar.ofNatCore_val_eq]
  by_cases h0 : b.val = 0
  · exact ⟨{ scan with valid := false }, by simp [h0], by simp [h0]⟩
  · by_cases h92 : b.val = 92
    · exact ⟨{ scan with valid := false }, by simp [h92], by simp [h92]⟩
    · by_cases h47 : b.val = 47
      · cases hv : scan.valid
        · exact ⟨{ valid := false, segment_len := 0#u8, only_dots := true },
            by simp [h47], by simp [h47]⟩
        · exact ⟨⟨decide (0 < scan.segment_len.val ∧
              ¬ (scan.only_dots = true ∧ scan.segment_len.val ≤ 2)), 0#u8, true⟩,
            by simp [h47, segment_ok_eq], by simp [h47]⟩
      · have hstep : ∃ i : U8,
            (if scan.segment_len.val < 3 then scan.segment_len + 1#u8 else ok 3#u8) = ok i ∧
              i.val = min 3 (scan.segment_len.val + 1) := by
          by_cases h3 : scan.segment_len.val < 3
          · have hb : scan.segment_len.val + (1#u8).val ≤ U8.max := by scalar_tac
            obtain ⟨i, hi, hiv⟩ := spec_imp_exists (U8.add_spec hb)
            refine ⟨i, by simp [h3, hi], ?_⟩
            scalar_tac
          · exact ⟨3#u8, by simp [h3], by scalar_tac⟩
        obtain ⟨i, hi, hiv⟩ := hstep
        cases hd : scan.only_dots
        · exact ⟨{ scan with segment_len := i }, by simp [h0, h92, h47, hi, hd],
            by simp [h0, h92, h47, hiv, hd]⟩
        · exact ⟨{ scan with segment_len := i, only_dots := decide (b.val = 46) },
            by simp [h0, h92, h47, hi], by simp [h0, h92, h47, hiv]⟩

/-! ## The canonical-path specification -/

/-- The segments of a path: the maximal runs of bytes between `/` bytes (47). A path with `k`
slashes has `k + 1` segments; the first and the last may be empty. -/
def segments : List U8 → List (List U8)
  | [] => [[]]
  | b :: rest =>
    if b.val = 47 then [] :: segments rest
    else (segments rest).modifyHead (fun seg => b :: seg)

/-- An acceptable segment: not empty, not `.` and not `..` (46 is the period). -/
def SegmentOk (seg : List U8) : Prop :=
  seg ≠ [] ∧ seg.map UScalar.val ≠ [46] ∧ seg.map UScalar.val ≠ [46, 46]

instance (seg : List U8) : Decidable (SegmentOk seg) := by unfold SegmentOk; infer_instance

/-- The canonical relative paths: no byte is NUL (0) or a backslash (92), and every segment of
the split on `/` is acceptable. -/
def canonicalSpec (l : List U8) : Bool :=
  l.all (fun b => decide (b.val ≠ 0 ∧ b.val ≠ 92)) &&
    (segments l).all (fun seg => decide (SegmentOk seg))

private theorem segments_ne_nil (l : List U8) : segments l ≠ [] := by
  induction l with
  | nil => simp [segments]
  | cons b rest ih =>
    obtain ⟨seg, segs, hs⟩ := List.exists_cons_of_ne_nil ih
    by_cases h47 : b.val = 47 <;> simp [segments, h47, hs]

private theorem eq_slash_of_val {b : U8} (h : b.val = 47) : b = 47#u8 := by
  rw [UScalar.eq_equiv]
  simp [h]

private theorem beq_slash (b : U8) : (b == 47#u8) = decide (b.val = 47) := by
  by_cases h : b.val = 47
  · simp [eq_slash_of_val h]
  · have hne : b ≠ 47#u8 := fun hb => h (by rw [hb]; rfl)
    simp [h, hne]

private theorem segments_eq_splitOn (l : List U8) : segments l = List.splitOn (47#u8) l := by
  unfold List.splitOn
  induction l with
  | nil => simp [segments]
  | cons b rest ih =>
    rw [segments, List.splitOnP_cons_eq_ite_modifyHead, ← ih, beq_slash]
    by_cases h47 : b.val = 47 <;> simp [h47]

private theorem segments_intercalate (l : List U8) :
    List.intercalate [47#u8] (segments l) = l := by
  induction l with
  | nil => simp [segments, List.intercalate]
  | cons b rest ih =>
    obtain ⟨seg, segs, hs⟩ := List.exists_cons_of_ne_nil (segments_ne_nil rest)
    rw [hs] at ih
    by_cases h47 : b.val = 47
    · simp [segments, h47, hs, List.intercalate] at ih ⊢
      exact ⟨(eq_slash_of_val h47).symm, ih⟩
    · cases segs with
      | nil =>
        simp [segments, h47, hs, List.intercalate] at ih ⊢
        exact ih
      | cons seg' segs' =>
        simp [segments, h47, hs, List.intercalate] at ih ⊢
        exact ih

private theorem segments_no_slash (l : List U8) :
    ∀ seg ∈ segments l, ∀ b ∈ seg, b.val ≠ 47 := by
  induction l with
  | nil => simp [segments]
  | cons x rest ih =>
    obtain ⟨seg, segs, hs⟩ := List.exists_cons_of_ne_nil (segments_ne_nil rest)
    rw [hs] at ih
    by_cases h47 : x.val = 47 <;> simpa [segments, h47, hs] using ih

/-- `segments` is the split on `/`: it agrees with the library split, joining the segments with
`/` gives the path back, and no segment contains a `/`. -/
theorem segments_spec (l : List U8) :
    segments l = List.splitOn (47#u8) l ∧
    List.intercalate [47#u8] (segments l) = l ∧
    ∀ seg ∈ segments l, ∀ b ∈ seg, b.val ≠ 47 :=
  ⟨segments_eq_splitOn l, segments_intercalate l, segments_no_slash l⟩

/-! The specification on small paths (97 is `a`, 98 is `b`, 47 is `/`, 46 is `.`). -/

/-- The segments of `a//b/` are `a`, the empty segment, `b` and the empty segment. -/
example : segments [97#u8, 47#u8, 47#u8, 98#u8, 47#u8] = [[97#u8], [], [98#u8], []] := by
  decide

/-- `a/b`, `...`, `.a` and `a.` are canonical. -/
example :
    canonicalSpec [97#u8, 47#u8, 98#u8] = true ∧
    canonicalSpec [46#u8, 46#u8, 46#u8] = true ∧
    canonicalSpec [46#u8, 97#u8] = true ∧
    canonicalSpec [97#u8, 46#u8] = true := by
  decide

/-- The empty path, `/a`, `a/`, `a//b`, `.`, `..`, `a/./b`, `a/../b`, a path with a backslash
and a path with a NUL are not canonical. -/
example :
    canonicalSpec [] = false ∧
    canonicalSpec [47#u8, 97#u8] = false ∧
    canonicalSpec [97#u8, 47#u8] = false ∧
    canonicalSpec [97#u8, 47#u8, 47#u8, 98#u8] = false ∧
    canonicalSpec [46#u8] = false ∧
    canonicalSpec [46#u8, 46#u8] = false ∧
    canonicalSpec [97#u8, 47#u8, 46#u8, 47#u8, 98#u8] = false ∧
    canonicalSpec [97#u8, 47#u8, 46#u8, 46#u8, 47#u8, 98#u8] = false ∧
    canonicalSpec [97#u8, 92#u8, 98#u8] = false ∧
    canonicalSpec [97#u8, 0#u8] = false := by
  decide

private theorem segments_append_slash (a c : List U8) (b : U8) (hb : b.val = 47) :
    segments (a ++ b :: c) = segments a ++ segments c := by
  induction a with
  | nil => simp [segments, hb]
  | cons x a ih =>
    obtain ⟨seg, segs, hs⟩ := List.exists_cons_of_ne_nil (segments_ne_nil a)
    by_cases h47 : x.val = 47 <;> simp [segments, h47, ih, hs]

private theorem not_segmentOk_nil : ¬ SegmentOk [] := by simp [SegmentOk]

private theorem canonicalSpec_eq_true_iff (l : List U8) :
    canonicalSpec l = true ↔
      (∀ b ∈ l, b.val ≠ 0 ∧ b.val ≠ 92) ∧ ∀ seg ∈ segments l, SegmentOk seg := by
  simp [canonicalSpec]

/-! ## The canonical-path scan -/

/-- The verdict on a finished segment, from its saturating length counter and all-periods
flag. -/
private def segOkN (n : Nat) (dots : Bool) : Bool := decide (0 < n ∧ ¬ (dots = true ∧ n ≤ 2))

/-- The verdict of a still-valid scan on the bytes it has not read yet, from the length counter
and all-periods flag of the current segment. -/
private def scanRest : Nat → Bool → List U8 → Bool
  | n, dots, [] => segOkN n dots
  | n, dots, b :: rest =>
    if b.val = 0 ∨ b.val = 92 then false
    else if b.val = 47 then segOkN n dots && scanRest 0 true rest
    else scanRest (min 3 (n + 1)) (dots && decide (b.val = 46)) rest

/-- One `path_step` does not change the verdict on the whole path. -/
private theorem path_step_scanRest (scan : PathScan) (b : U8) :
    ∃ next, path_step scan b = ok next ∧
      ∀ rest, (next.valid && scanRest next.segment_len.val next.only_dots rest) =
        (scan.valid && scanRest scan.segment_len.val scan.only_dots (b :: rest)) := by
  obtain ⟨next, hnext, hbad, hslash, hother⟩ := path_step_spec scan b
  refine ⟨next, hnext, fun rest => ?_⟩
  by_cases h0 : b.val = 0
  · obtain ⟨hv, -, -⟩ := hbad (Or.inl h0)
    simp [scanRest, h0, hv]
  · by_cases h92 : b.val = 92
    · obtain ⟨hv, -, -⟩ := hbad (Or.inr h92)
      simp [scanRest, h92, hv]
    · by_cases h47 : b.val = 47
      · obtain ⟨hv, hl, hd⟩ := hslash h47
        simp [scanRest, h47, hv, hl, hd, segOkN, Bool.and_assoc]
      · obtain ⟨hv, hl, hd⟩ := hother h0 h92 h47
        simp [scanRest, h0, h92, h47, hv, hl, hd]

/-- The scan from any state. The invariant is that the verdict on the whole path, computed from
the current scan state and the bytes not read yet, never changes; the measure is the number of
bytes not read yet. -/
private theorem path_loop_spec (s : Slice U8) (scan : PathScan) (index : Usize)
    (hindex : index.val ≤ s.val.length) :
    is_canonical_relative_path_loop s scan index ⦃ r =>
      (r.valid && segOkN r.segment_len.val r.only_dots) =
        (scan.valid && scanRest scan.segment_len.val scan.only_dots (s.val.drop index.val)) ⦄ := by
  unfold is_canonical_relative_path_loop
  apply loop.spec_decr_nat
    (fun (x : PathScan × Usize) => s.val.length - x.2.val)
    (fun (x : PathScan × Usize) => x.2.val ≤ s.val.length ∧
      (x.1.valid && scanRest x.1.segment_len.val x.1.only_dots (s.val.drop x.2.val)) =
        (scan.valid && scanRest scan.segment_len.val scan.only_dots (s.val.drop index.val)))
  · rintro ⟨sc, i⟩ ⟨hi, hinv⟩
    simp only at hi hinv ⊢
    unfold is_canonical_relative_path_loop.body
    by_cases hlt : i < Slice.len s
    · have hlt' : i.val < s.val.length := by scalar_tac
      cases hv : sc.valid with
      | true =>
        obtain ⟨j, hj, hjv⟩ := usize_add_one_eq s hlt'
        obtain ⟨sc1, hsc1, hstep⟩ := path_step_scanRest sc s.val[i.val]
        simp only [hlt, ↓reduceIte, index_usize_eq s i hlt', bind_ok, hsc1, hj, WP.spec_ok]
        refine ⟨⟨by omega, ?_⟩, by omega⟩
        rw [← hinv, hjv, List.drop_eq_getElem_cons hlt', hstep]
      | false =>
        simp only [hlt, ↓reduceIte, Bool.false_eq_true, WP.spec_ok]
        rw [← hinv]
        simp [hv]
    · have hge : i.val = s.val.length := by scalar_tac
      simp only [hlt, ↓reduceIte, WP.spec_ok]
      rw [← hinv, hge]
      simp [scanRest]
  · exact ⟨hindex, rfl⟩

/-- The length counter saturating at three and the all-periods flag decide whether a segment is
acceptable. -/
private theorem segOkN_eq (cur : List U8) :
    segOkN (min 3 cur.length) (cur.all (fun b => decide (b.val = 46))) =
      decide (SegmentOk cur) := by
  rcases cur with _ | ⟨a, _ | ⟨b, _ | ⟨c, t⟩⟩⟩
  · simp [segOkN, SegmentOk]
  · simp [segOkN, SegmentOk]
  · simp [segOkN, SegmentOk]
  · simp [segOkN, SegmentOk]

/-- The verdict of the scan, started inside a segment whose bytes so far are `cur`, is the
specification of the remaining bytes with `cur` put in front of their first segment. -/
private theorem scanRest_eq (rest : List U8) : ∀ cur : List U8,
    scanRest (min 3 cur.length) (cur.all (fun b => decide (b.val = 46))) rest =
      (rest.all (fun b => decide (b.val ≠ 0 ∧ b.val ≠ 92)) &&
        ((segments rest).modifyHead (fun seg => cur ++ seg)).all
          (fun seg => decide (SegmentOk seg))) := by
  induction rest with
  | nil =>
    intro cur
    simp [scanRest, segments, segOkN_eq]
  | cons b rest ih =>
    intro cur
    obtain ⟨seg, segs, hs⟩ := List.exists_cons_of_ne_nil (segments_ne_nil rest)
    by_cases h0 : b.val = 0
    · simp [scanRest, h0]
    · by_cases h92 : b.val = 92
      · simp [scanRest, h92]
      · by_cases h47 : b.val = 47
        · have hnil := ih []
          simp [hs] at hnil
          simp [scanRest, h47, segments, hs, segOkN_eq, hnil]
          exact Bool.and_left_comm _ _ _
        · have hcons := ih (cur ++ [b])
          have hmin : min 3 (min 3 cur.length + 1) = min 3 (cur.length + 1) := by omega
          simp [hs] at hcons
          simp [scanRest, h0, h92, h47, segments, hs, hmin, hcons]

/-! ## `is_canonical_relative_path` -/

/-- `is_canonical_relative_path` never fails and computes exactly the specification: it answers
`true` exactly when no byte is NUL or a backslash and every segment of the split on `/` is
non-empty and is neither `.` nor `..`. -/
theorem is_canonical_relative_path_iff (s : Slice U8) :
    is_canonical_relative_path s = ok (canonicalSpec s.val) := by
  obtain ⟨r, hr, hv⟩ := spec_imp_exists
    (path_loop_spec s { valid := true, segment_len := 0#u8, only_dots := true } 0#usize
      (by simp))
  have hspec := scanRest_eq s.val []
  obtain ⟨seg, segs, hs⟩ := List.exists_cons_of_ne_nil (segments_ne_nil s.val)
  unfold is_canonical_relative_path
  simp [hs] at hspec
  simp at hv
  have hres : (if r.valid = true then segment_ok r.segment_len r.only_dots else ok false) =
      ok (r.valid && segOkN r.segment_len.val r.only_dots) := by
    cases r.valid <;> simp [segment_ok_eq, segOkN]
  rw [hr]
  simp only [bind_ok]
  rw [hres, hv, hspec]
  simp [canonicalSpec, hs]

/-- `is_canonical_relative_path` never fails. -/
theorem is_canonical_relative_path_total (s : Slice U8) :
    ∃ v, is_canonical_relative_path s = ok v :=
  ⟨_, is_canonical_relative_path_iff s⟩

private theorem spec_of_ok_true {s : Slice U8} (h : is_canonical_relative_path s = ok true) :
    (∀ b ∈ s.val, b.val ≠ 0 ∧ b.val ≠ 92) ∧ ∀ seg ∈ segments s.val, SegmentOk seg := by
  rw [is_canonical_relative_path_iff] at h
  exact (canonicalSpec_eq_true_iff s.val).mp (by simpa using h)

/-- A canonical path is not empty. -/
theorem canonical_path_not_empty (s : Slice U8) (h : is_canonical_relative_path s = ok true) :
    s.val ≠ [] := by
  intro hnil
  exact not_segmentOk_nil ((spec_of_ok_true h).2 [] (by simp [hnil, segments]))

/-- A canonical path contains no NUL byte and no backslash. -/
theorem canonical_path_no_nul_or_backslash (s : Slice U8)
    (h : is_canonical_relative_path s = ok true) :
    ∀ b ∈ s.val, b.val ≠ 0 ∧ b.val ≠ 92 :=
  (spec_of_ok_true h).1

/-- A canonical path has a first byte, and it is not a slash. -/
theorem canonical_path_no_leading_slash (s : Slice U8)
    (h : is_canonical_relative_path s = ok true) :
    ∃ b, s.val.head? = some b ∧ b.val ≠ 47 := by
  cases hl : s.val with
  | nil => exact absurd hl (canonical_path_not_empty s h)
  | cons b rest =>
    refine ⟨b, rfl, fun h47 => ?_⟩
    exact not_segmentOk_nil ((spec_of_ok_true h).2 [] (by simp [hl, segments, h47]))

/-- A canonical path has a last byte, and it is not a slash. -/
theorem canonical_path_no_trailing_slash (s : Slice U8)
    (h : is_canonical_relative_path s = ok true) :
    ∃ b, s.val.getLast? = some b ∧ b.val ≠ 47 := by
  have hne := canonical_path_not_empty s h
  have hl : s.val = s.val.dropLast ++ [s.val.getLast hne] :=
    (List.dropLast_append_getLast hne).symm
  refine ⟨s.val.getLast hne, List.getLast?_eq_some_getLast hne, fun h47 => ?_⟩
  refine not_segmentOk_nil ((spec_of_ok_true h).2 [] ?_)
  rw [hl, segments_append_slash _ [] _ h47]
  simp [segments]

/-- A canonical path has no empty segment between slashes: no two adjacent bytes are both
slashes. -/
theorem canonical_path_no_empty_segment (s : Slice U8)
    (h : is_canonical_relative_path s = ok true) :
    ∀ i a b, s.val[i]? = some a → s.val[i + 1]? = some b → ¬ (a.val = 47 ∧ b.val = 47) := by
  intro i a b ha hb ⟨ha47, hb47⟩
  obtain ⟨hi, rfl⟩ := List.getElem?_eq_some_iff.mp ha
  obtain ⟨hi1, rfl⟩ := List.getElem?_eq_some_iff.mp hb
  have hl : s.val = s.val.take i ++ s.val[i] :: s.val[i + 1] :: s.val.drop (i + 1 + 1) := by
    rw [← List.drop_eq_getElem_cons hi1, ← List.drop_eq_getElem_cons hi, List.take_append_drop]
  refine not_segmentOk_nil ((spec_of_ok_true h).2 [] ?_)
  rw [hl, segments_append_slash _ _ _ ha47]
  simp [segments, hb47]

/-- No segment of a canonical path, the first and the last included, is `.` or `..`. -/
theorem canonical_path_no_dot_segments (s : Slice U8)
    (h : is_canonical_relative_path s = ok true) :
    ∀ seg ∈ segments s.val, seg.map UScalar.val ≠ [46] ∧ seg.map UScalar.val ≠ [46, 46] :=
  fun seg hseg => ((spec_of_ok_true h).2 seg hseg).2

end mneme_kernel.text
