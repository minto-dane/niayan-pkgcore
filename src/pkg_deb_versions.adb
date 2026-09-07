-- SPDX-License-Identifier: MIT
package body Pkg_Deb_Versions with SPARK_Mode is
   Max_Epoch : constant := 2_147_483_647;
   type Parts is record
      Epoch : Natural := 0;
      First_Up, Last_Up : Integer := 1;
      First_Rev, Last_Rev : Integer := 1;
      Has_Revision : Boolean := False;
   end record;
   function Digit (C : Character) return Boolean is (C in '0' .. '9');
   function Alpha (C : Character) return Boolean is
     (C in 'a' .. 'z' or else C in 'A' .. 'Z');
   procedure Split (Text : String; P : out Parts; OK : out Boolean) is
      Colon, Dash : Integer := 0;
      Value : Natural := 0;
      D : Natural;
   begin
      P := (others => <>); OK := False;
      if Text'Length = 0 or else Text'Length > Max_Length
        or else Text'Last >= Integer'Last - 1 then return; end if;
      for I in Text'Range loop
         if Text (I) = ':' and then Colon = 0 then Colon := I; end if;
      end loop;
      P.First_Up := Text'First;
      if Colon /= 0 then
         if Colon = Text'First or else Colon = Text'Last then return; end if;
         for I in Text'First .. Colon - 1 loop
            if not Digit (Text (I)) then return; end if;
            D := Character'Pos (Text (I)) - Character'Pos ('0');
            if Value > (Max_Epoch - D) / 10 then return; end if;
            Value := Value * 10 + D;
         end loop;
         P.Epoch := Value; P.First_Up := Colon + 1;
      end if;
      if not Digit (Text (P.First_Up)) then return; end if;
      for I in P.First_Up .. Text'Last loop
         if Text (I) = '-' then Dash := I; end if;
      end loop;
      P.Last_Up := Text'Last;
      if Dash /= 0 then
         if Dash = P.First_Up or else Dash = Text'Last then return; end if;
         P.Last_Up := Dash - 1; P.First_Rev := Dash + 1;
         P.Last_Rev := Text'Last; P.Has_Revision := True;
         for I in P.First_Rev .. P.Last_Rev loop
            if not (Digit (Text (I)) or else Alpha (Text (I))
              or else Text (I) in '.' | '+' | '~') then return; end if;
         end loop;
      end if;
      for I in P.First_Up .. P.Last_Up loop
         if not (Digit (Text (I)) or else Alpha (Text (I))
           or else Text (I) in '.' | '+' | ':' | '~' | '-') then return; end if;
      end loop;
      OK := True;
   end Split;
   function Valid (Text : String) return Boolean is
      P : Parts; OK : Boolean;
   begin
      Split (Text, P, OK); return OK;
   end Valid;
   function Weight (S : String; I : Integer) return Integer is
   begin
      if I > S'Last then return 0; end if;
      if S (I) = '~' then return -1; end if;
      if Digit (S (I)) then return 0; end if;
      if Alpha (S (I)) then return Character'Pos (S (I)); end if;
      return Character'Pos (S (I)) + 256;
   end Weight;
   function Part_Order (A, B : String) return Ordering is
      I : Integer := A'First; J : Integer := B'First;
      LA, LB, SA, SB : Integer;
      WA, WB : Integer;
   begin
      while I <= A'Last or else J <= B'Last loop
         while (I <= A'Last and then not Digit (A (I)))
           or else (J <= B'Last and then not Digit (B (J))) loop
            WA := Weight (A, I); WB := Weight (B, J);
            if WA < WB then return Older; elsif WA > WB then return Newer; end if;
            if I <= A'Last then I := I + 1; end if;
            if J <= B'Last then J := J + 1; end if;
         end loop;
         while I <= A'Last and then A (I) = '0' loop I := I + 1; end loop;
         while J <= B'Last and then B (J) = '0' loop J := J + 1; end loop;
         SA := I; SB := J;
         while I <= A'Last and then Digit (A (I)) loop I := I + 1; end loop;
         while J <= B'Last and then Digit (B (J)) loop J := J + 1; end loop;
         LA := I - SA; LB := J - SB;
         if LA < LB then return Older; elsif LA > LB then return Newer; end if;
         while SA < I loop
            if A (SA) < B (SB) then return Older;
            elsif A (SA) > B (SB) then return Newer; end if;
            SA := SA + 1; SB := SB + 1;
         end loop;
      end loop;
      return Equal;
   end Part_Order;
   function Compare (Left, Right : String) return Ordering is
      L, R : Parts; L_OK, R_OK : Boolean; Result : Ordering;
   begin
      Split (Left, L, L_OK); Split (Right, R, R_OK);
      pragma Assert (L_OK and R_OK);
      if L.Epoch < R.Epoch then return Older;
      elsif L.Epoch > R.Epoch then return Newer; end if;
      Result := Part_Order (Left (L.First_Up .. L.Last_Up), Right (R.First_Up .. R.Last_Up));
      if Result /= Equal then return Result; end if;
      if L.Has_Revision and R.Has_Revision then
         return Part_Order (Left (L.First_Rev .. L.Last_Rev), Right (R.First_Rev .. R.Last_Rev));
      elsif L.Has_Revision then return Part_Order (Left (L.First_Rev .. L.Last_Rev), "0");
      elsif R.Has_Revision then return Part_Order ("0", Right (R.First_Rev .. R.Last_Rev));
      else return Equal; end if;
   end Compare;
end Pkg_Deb_Versions;
