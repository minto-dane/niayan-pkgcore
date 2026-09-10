-- SPDX-License-Identifier: BSD-3-Clause
with Resolver_Proof;
package body Resolver_LRAT with SPARK_Mode is
   use type Byte;
   procedure Check (F : Resolver_CNF.Formula; Proof : Bytes;
      Workspace : in out Resolver_Proof.Database;
      Accepted : out Boolean; Status : out Outcome; Fuel : in out Natural) is
      D : Resolver_Proof.Database renames Workspace;
      C : Resolver_Proof.Literals (1 .. Resolver_CNF.Max_Variables * 2) := (others => 0);
      P, Line_End : Natural;
      ID, X : Counter; Negative : Boolean;
      Count : Natural range 0..C'Length;
      Hint_Count : Natural range 0..Resolver_Proof.Max_Entries*2;
      Bad : Boolean := False; Is_Delete : Boolean;
      function Cursor_Valid return Boolean is
        (Proof'First=1 and then Proof'Length in 1..Max_Proof_Bytes
         and then Line_End in Proof'Range and then P in Proof'First..Line_End);
      procedure Spaces with Pre => Cursor_Valid,
        Post => Cursor_Valid and then P>=P'Old
      is
      begin
         while P < Line_End and then Proof(P)=32 loop
            pragma Loop_Invariant(Cursor_Valid and then P>=P'Loop_Entry);
            pragma Loop_Variant(Increases=>P);
            P:=P+1;
         end loop;
      end;
      procedure Number (V : out Counter; Neg : out Boolean) with
        Pre => Cursor_Valid,
        Post => Cursor_Valid and then P>=P'Old and then (if not Bad then P>P'Old)
      is
         Start : Natural; Digit : Counter;
      begin
         V := 0; Neg := False; Spaces;
         if P >= Line_End then Bad := True; return; end if;
         if Proof (P) = 45 then Neg := True; P := P + 1; end if;
         Start := P;
         while P < Line_End and then Proof (P) in 48 .. 57 loop
            pragma Loop_Invariant(Cursor_Valid and then P>=Start);
            pragma Loop_Variant(Increases=>P);
            if Fuel = 0 then Bad := True; return; end if; Fuel := Fuel - 1;
            Digit := Counter (Proof (P) - 48);
            if V > (Counter'Last - Digit) / 10 then Bad := True; return; end if;
            V := V * 10 + Digit; P := P + 1;
         end loop;
         if P = Start or else (P < Line_End and then Proof (P) /= 32)
         then Bad := True; end if;
      end Number;
   begin
      Accepted := False; Status := Invalid_Input;
      if Proof'First /= 1 or else Proof'Length = 0 or else Proof'Length > Max_Proof_Bytes
        or else Proof (Proof'Last) /= 10 then return; end if;
      P:=Proof'First;
      Resolver_Proof.Initialize (F, D, Status, Fuel); if Status /= OK then return; end if;
      while P <= Proof'Last loop
         pragma Loop_Invariant(P in Proof'First..Proof'Last+1);
         pragma Loop_Variant(Increases=>P);
         Line_End := P;
         while Line_End <= Proof'Last and then Proof (Line_End) /= 10 loop
            pragma Loop_Invariant(Line_End in P..Proof'Last+1);
            pragma Loop_Variant(Increases=>Line_End);
            if Fuel = 0 then Status := Exhausted; return; end if; Fuel := Fuel - 1;
            if Proof (Line_End) < 32 or else Proof (Line_End) > 126 then Status := Invalid_Input; return; end if;
            Line_End := Line_End + 1;
         end loop;
         if Line_End > Proof'Last or else Line_End = P then Status := Invalid_Input; return; end if;
         -- Comments are not inference steps and cannot contain binary data.
         if Proof (P) = 99 and then P + 1 < Line_End and then Proof (P + 1) = 32 then
            P := Line_End + 1;
         else
            Number (ID, Negative);
            if Bad or else Negative or else ID = 0 then Status := Invalid_Input; return; end if;
            Spaces; Is_Delete := P < Line_End and then Proof (P) = 100;
            if Is_Delete then
               P := P + 1;
               if P >= Line_End or else Proof (P) /= 32 then Status := Invalid_Input; return; end if;
               loop
                  pragma Loop_Invariant(Cursor_Valid);
                  pragma Loop_Variant(Increases=>P);
                  Number (X, Negative);
                  if Bad or else Negative then Status := Invalid_Input; return; end if;
                  exit when X = 0;
                  Resolver_Proof.Delete (D, X, Status, Fuel); if Status /= OK then return; end if;
               end loop;
            else
               Count := 0;
               loop
                  pragma Loop_Invariant(Cursor_Valid);
                  pragma Loop_Variant(Increases=>P);
                  Number (X, Negative);
                  if Bad or else (Negative and then X=0) or else X > Counter (F.Variables) then Status := Invalid_Input; return; end if;
                  exit when X = 0;
                  if Count = C'Length then Status := Exhausted; return; end if;
                  Count := Count + 1;
                  C (Count) := (if Negative then -Integer (X) else Integer (X));
               end loop;
               Hint_Count := 0;
               loop
                  pragma Loop_Invariant(Cursor_Valid);
                  pragma Loop_Variant(Increases=>P);
                  Number (X, Negative); if Bad or else (Negative and then X=0) then Status := Invalid_Input; return; end if;
                  exit when X = 0;
                  if Hint_Count=Resolver_Proof.Max_Entries*2 then Status:=Exhausted; return; end if;
                  Hint_Count := Hint_Count + 1;
                  -- The signed hint ID is deliberately NOT used as a trusted
                  -- reason. RUP/RAT scans all active clauses independently.
               end loop;
               Resolver_Proof.Add (D, ID, C (1 .. Count), Status, Fuel); if Status /= OK then return; end if;
            end if;
            Spaces; if P /= Line_End then Status := Invalid_Input; return; end if;
            P := Line_End + 1;
         end if;
      end loop;
      Accepted := Resolver_Proof.Refuted (D);
      if not Accepted then Status := Denied; else Status := OK; end if;
   end Check;
end Resolver_LRAT;
