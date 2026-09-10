-- SPDX-License-Identifier: BSD-3-Clause
package body Pkg_Versions with SPARK_Mode is
   function Digit (C : Character) return Boolean is (C in '0' .. '9');
   function Alpha (C : Character) return Boolean is
     (C in 'a' .. 'z' or else C in 'A' .. 'Z');
   function Special (C : Character) return Boolean is
     (Digit (C) or else Alpha (C) or else C = '~' or else C = '^');
   function Compare_Parts (Left, Right : String) return Ordering with
     Pre => Left'First=1 and then Right'First=1
       and then Left'Last=Left'Length and then Right'Last=Right'Length
       and then Left'Length<=4_096 and then Right'Length<=4_096
   is
      L : Integer := Left'First;
      R : Integer := Right'First;
      LE, RE, LS, RS : Integer;
      Numeric : Boolean;
      function Cursors return Boolean is
        (Left'Last in 0..4_096 and then Right'Last in 0..4_096
         and then L in 1..Left'Last+1 and then R in 1..Right'Last+1);
   begin
      if Left = Right then return Equal; end if;
      loop
         pragma Loop_Invariant(Cursors);
         pragma Loop_Variant(Increases=>L, Increases=>R);
         while L <= Left'Last and then not Special (Left (L)) loop pragma Loop_Invariant(Cursors and then L>=L'Loop_Entry); pragma Loop_Variant(Increases=>L); L := L + 1; end loop;
         while R <= Right'Last and then not Special (Right (R)) loop pragma Loop_Invariant(Cursors and then R>=R'Loop_Entry); pragma Loop_Variant(Increases=>R); R := R + 1; end loop;
         if (L <= Left'Last and then Left (L) = '~')
           or else (R <= Right'Last and then Right (R) = '~')
         then
            if L > Left'Last or else Left (L) /= '~' then return Newer; end if;
            if R > Right'Last or else Right (R) /= '~' then return Older; end if;
            L := L + 1; R := R + 1;
         elsif (L <= Left'Last and then Left (L) = '^')
           or else (R <= Right'Last and then Right (R) = '^')
         then
            if L > Left'Last then return Older; end if;
            if R > Right'Last then return Newer; end if;
            if Left (L) /= '^' then return Newer; end if;
            if Right (R) /= '^' then return Older; end if;
            L := L + 1; R := R + 1;
         else
            exit when L > Left'Last or else R > Right'Last;
            Numeric := Digit (Left (L));
            LE := L; RE := R;
            if Numeric then
               while LE <= Left'Last and then Digit (Left (LE)) loop pragma Loop_Invariant(LE in L..Left'Last+1); pragma Loop_Variant(Increases=>LE); LE := LE + 1; end loop;
               while RE <= Right'Last and then Digit (Right (RE)) loop pragma Loop_Invariant(RE in R..Right'Last+1); pragma Loop_Variant(Increases=>RE); RE := RE + 1; end loop;
            else
               while LE <= Left'Last and then Alpha (Left (LE)) loop pragma Loop_Invariant(LE in L..Left'Last+1); pragma Loop_Variant(Increases=>LE); LE := LE + 1; end loop;
               while RE <= Right'Last and then Alpha (Right (RE)) loop pragma Loop_Invariant(RE in R..Right'Last+1); pragma Loop_Variant(Increases=>RE); RE := RE + 1; end loop;
            end if;
            if RE = R then
               if Numeric then return Newer; else return Older; end if;
            end if;
            LS := L; RS := R;
            if Numeric then
               while LS < LE and then Left (LS) = '0' loop pragma Loop_Invariant(LS in L..LE); pragma Loop_Variant(Increases=>LS); LS := LS + 1; end loop;
               while RS < RE and then Right (RS) = '0' loop pragma Loop_Invariant(RS in R..RE); pragma Loop_Variant(Increases=>RS); RS := RS + 1; end loop;
               if LE - LS > RE - RS then return Newer; end if;
               if LE - LS < RE - RS then return Older; end if;
            end if;
            while LS < LE and then RS < RE loop
               pragma Loop_Invariant(LS in L..LE and then RS in R..RE);
               pragma Loop_Variant(Increases=>LS);
               if Left (LS) < Right (RS) then return Older; end if;
               if Left (LS) > Right (RS) then return Newer; end if;
               LS := LS + 1; RS := RS + 1;
            end loop;
            if LS < LE then return Newer; end if;
            if RS < RE then return Older; end if;
            L := LE; R := RE;
         end if;
      end loop;
      if L > Left'Last and then R > Right'Last then return Equal; end if;
      if L > Left'Last then return Older; else return Newer; end if;
   end Compare_Parts;
   function Compare (Left, Right : String) return Ordering is
      -- Normalize caller-supplied index origins, including unusual null ranges.
      L : constant String(1..Left'Length):=Left;
      R : constant String(1..Right'Length):=Right;
   begin
      return Compare_Parts(L,R);
   end Compare;
end Pkg_Versions;
