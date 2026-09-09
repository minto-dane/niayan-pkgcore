-- SPDX-License-Identifier: MIT
with Ada.Characters.Handling;
with MC_SHA256; with Pkg_Deb_Versions;
package body Pkg_Deb_Fields with SPARK_Mode => Off is
   use type Byte; use type Pkg_Deb_Semantics.Multi_Arch;
   function Lower (S : String) return String renames Ada.Characters.Handling.To_Lower;
   function Char (Raw : Bytes; Offset : Natural) return Character is
     (Character'Val (Raw (Raw'First + Offset)));
   function White (C : Character) return Boolean is (C in ' ' | ASCII.HT);
   function Slice (Raw : Bytes; First, Last : Natural) return String is
      S : String (1 .. Last - First);
   begin
      for I in S'Range loop S (I) := Char (Raw, First + I - 1); end loop;
      return S;
   end Slice;
   function Valid_UTF8 (Raw : Bytes) return Boolean is
      I : Natural := 0; Width : Positive; First, Second : Byte;
   begin
      while I < Raw'Length loop
         First := Raw (Raw'First + I);
         if First < 128 then
            if First < 32 and then First not in 9 | 10 | 13 then return False; end if;
            if First = 13 and then (I + 1 = Raw'Length or else Raw (Raw'First + I + 1) /= 10) then return False; end if;
            if First = 127 then return False; end if;
            I := I + 1;
         else
            if First in 16#C2# .. 16#DF# then Width := 2;
            elsif First in 16#E0# .. 16#EF# then Width := 3;
            elsif First in 16#F0# .. 16#F4# then Width := 4;
            else return False; end if;
            if Raw'Length - I < Width then return False; end if;
            for J in 1 .. Width - 1 loop
               if Raw (Raw'First + I + J) not in 16#80# .. 16#BF# then return False; end if;
            end loop;
            Second := Raw (Raw'First + I + 1);
            if (First = 16#E0# and then Second < 16#A0#) or else (First = 16#ED# and then Second > 16#9F#)
               or else (First = 16#F0# and then Second < 16#90#) or else (First = 16#F4# and then Second > 16#8F#) then
               return False;
            end if;
            I := I + Width;
         end if;
      end loop;
      return True;
   end Valid_UTF8;
   function Find (Parsed : Document; Name : String) return Natural is
      Key : constant String := Lower (Name);
   begin
      for I in 1 .. Parsed.Count loop
         if MC_Text.Image (Parsed.Fields (I).Name) = Key then return I; end if;
      end loop;
      return 0;
   end Find;
   function Field_Count (Parsed : Document) return Natural is (Parsed.Count);
   function Field_Name (Parsed : Document; Index : Positive) return String is
     (if Index <= Parsed.Count then MC_Text.Image (Parsed.Fields (Index).Name) else "");
   function Content_Hash (Parsed : Document) return Digest is (Parsed.Hash);
   function Has_Field (Parsed : Document; Name : String) return Boolean is (Find (Parsed, Name) /= 0);
   procedure Parse (Raw : Bytes; Result : out Document; Status : out Outcome) is
      Candidate : Document; Position, Ending, Last, Colon : Natural := 0;
      Stanza_Ended, Nonempty : Boolean := False;
   begin
      Result := (others => <>); Status := Exhausted;
      if Raw'Length > Max_Control then return; end if;
      Status := Invalid_Input;
      if Raw'Length = 0 or else not Valid_UTF8 (Raw) then return; end if;
      while Position < Raw'Length loop
         Ending := Position;
         while Ending < Raw'Length and then Char (Raw, Ending) /= ASCII.LF loop Ending := Ending + 1; end loop;
         Last := Ending;
         if Last > Position and then Char (Raw, Last - 1) = ASCII.CR then Last := Last - 1; end if;
         if Last - Position > Max_Line then Status := Exhausted; return; end if;
         Nonempty := False;
         for I in Position .. Last - 1 loop
            if not White (Char (Raw, I)) then Nonempty := True; exit; end if;
         end loop;
         if not Nonempty then
            if Candidate.Count > 0 then Stanza_Ended := True; end if;
         else
            if Stanza_Ended then return; end if;
            if White (Char (Raw, Position)) then
               if Candidate.Count = 0 then return; end if;
               Candidate.Fields (Candidate.Count).Last := Last;
               Candidate.Fields (Candidate.Count).Continuations := Candidate.Fields (Candidate.Count).Continuations + 1;
            else
               if Candidate.Count = Max_Fields then Status := Exhausted; return; end if;
               Colon := Position;
               while Colon < Last and then Char (Raw, Colon) /= ':' loop
                  if Char (Raw, Colon) not in '!' .. '~' then return; end if;
                  Colon := Colon + 1;
               end loop;
               if Colon = Position or else Colon = Last or else Char (Raw, Position) in '#' | '-' then return; end if;
               if Colon - Position > MC_Text.Max_Length then Status := Exhausted; return; end if;
               declare Name : constant String := Lower (Slice (Raw, Position, Colon)); begin
                  if Find (Candidate, Name) /= 0 then return; end if;
                  Candidate.Count := Candidate.Count + 1;
                  MC_Text.Set (Candidate.Fields (Candidate.Count).Name, Name, Status);
                  if Status /= OK then return; end if;
                  Status := Invalid_Input;
               end;
               Candidate.Fields (Candidate.Count).First := Colon + 1;
               Candidate.Fields (Candidate.Count).Last := Last;
            end if;
         end if;
         Position := (if Ending < Raw'Length then Ending + 1 else Ending);
      end loop;
      if Candidate.Count = 0 then return; end if;
      for F of Candidate.Fields (1 .. Candidate.Count) loop
         Nonempty := False;
         for I in F.First .. F.Last - 1 loop
            if Char (Raw, I) not in ' ' | ASCII.HT | ASCII.CR | ASCII.LF then Nonempty := True; exit; end if;
         end loop;
         if not Nonempty then return; end if;
      end loop;
      Candidate.Size := Raw'Length; Candidate.Hash := MC_SHA256.Hash (Raw);
      Result := Candidate; Status := OK;
   exception when others => Result := (others => <>); Status := Invalid_Input;
   end Parse;
   procedure Read_Value (Raw : Bytes; Parsed : Document; Name : String;
                         Layout : Value_Layout; Value : out Bytes;
                         Used : out Natural; Status : out Outcome) is
      Index : constant Natural := Find (Parsed, Name);
      First, Last, Count, Position, Ending : Natural := 0; First_Line : Boolean := True;
      Pending_Space : Boolean := False;
      procedure Append (C : Character) is
      begin
         if Count = Value'Length then Status := Exhausted; return; end if;
         Value (Value'First + Count) := Character'Pos (C); Count := Count + 1;
      end Append;
   begin
      Value := (others => 0); Used := 0; Status := Invalid_Input;
      if Index = 0 or else Parsed.Hash = Zero_Digest then return; end if;
      if Raw'Length /= Parsed.Size or else MC_SHA256.Hash (Raw) /= Parsed.Hash then Status := Conflict; return; end if;
      if Layout = Simple and then Parsed.Fields (Index).Continuations /= 0 then return; end if;
      First := Parsed.Fields (Index).First; Last := Parsed.Fields (Index).Last; Status := OK;
      if Layout = Raw_Field then
         for I in First .. Last - 1 loop Append (Char (Raw, I)); exit when Status /= OK; end loop;
      elsif Layout = Folded then
         for I in First .. Last - 1 loop
            if Char (Raw, I) in ' ' | ASCII.HT | ASCII.CR | ASCII.LF then
               Pending_Space := Count > 0;
            else
               if Pending_Space then Append (' '); exit when Status /= OK; end if;
               Append (Char (Raw, I)); exit when Status /= OK; Pending_Space := False;
            end if;
         end loop;
      else
         Position := First;
         loop
            Ending := Position;
            while Ending < Last and then Char (Raw, Ending) /= ASCII.LF loop Ending := Ending + 1; end loop;
            declare A : Natural := Position; B : Natural := Ending; begin
               if B > A and then Char (Raw, B - 1) = ASCII.CR then B := B - 1; end if;
               if First_Line then
                  while A < B and then White (Char (Raw, A)) loop A := A + 1; end loop;
                  while B > A and then White (Char (Raw, B - 1)) loop B := B - 1; end loop;
               else
                  Append (ASCII.LF);
                  if A < B and then White (Char (Raw, A)) then A := A + 1; end if;
               end if;
               for I in A .. B - 1 loop exit when Status /= OK; Append (Char (Raw, I)); end loop;
            end;
            exit when Status /= OK or else Ending = Last;
            First_Line := False; Position := Ending + 1;
         end loop;
      end if;
      if Status = OK then Used := Count; else Value := (others => 0); end if;
   exception when others => Value := (others => 0); Used := 0; Status := Invalid_Input;
   end Read_Value;
   function Package_Name (Name : String) return Boolean is
   begin
      if Name'Length < 2 or else Name (Name'First) not in 'a' .. 'z' | '0' .. '9' then return False; end if;
      for C of Name loop
         if C not in 'a' .. 'z' | '0' .. '9' | '+' | '-' | '.' then return False; end if;
      end loop;
      return True;
   end Package_Name;
   procedure Check_Identity (Raw : Bytes; Parsed : Document;
                             Result : out Metadata; Status : out Outcome) is
      Candidate : Metadata; Buffer : Bytes (1 .. MC_Text.Max_Length); Used : Natural; Text : MC_Text.Value;
      procedure Get (Name : String; Value : out MC_Text.Value) is
      begin
         Value := MC_Text.Empty; Read_Value (Raw, Parsed, Name, Simple, Buffer, Used, Status);
         if Status = OK then MC_Text.Set (Value, Slice (Buffer, 0, Used), Status); end if;
      end Get;
      procedure Flag (Name : String; Value : out Boolean) is
      begin
         Value := False; Status := OK;
         if not Has_Field (Parsed, Name) then return; end if;
         Get (Name, Text); if Status /= OK then return; end if;
         if MC_Text.Image (Text) = "yes" then Value := True;
         elsif MC_Text.Image (Text) /= "no" then Status := Invalid_Input; end if;
      end Flag;
   begin
      Result := (others => <>);
      Get ("package", Candidate.Name); if Status /= OK then return; end if;
      if not Package_Name (MC_Text.Image (Candidate.Name)) then Status := Invalid_Input; return; end if;
      Get ("version", Candidate.Version); if Status /= OK then return; end if;
      if not Pkg_Deb_Versions.Valid (MC_Text.Image (Candidate.Version)) then Status := Invalid_Input; return; end if;
      Get ("architecture", Candidate.Architecture); if Status /= OK then return; end if;
      declare Arch : constant String := MC_Text.Image (Candidate.Architecture); begin
         if Arch'Length = 0 or else Arch in "any" | "source" or else Arch (1) not in 'a' .. 'z' | '0' .. '9' then
            Status := Invalid_Input; return;
         end if;
         for C of Arch loop
            if C not in 'a' .. 'z' | '0' .. '9' | '-' then Status := Invalid_Input; return; end if;
         end loop;
      end;
      Get ("maintainer", Text); if Status /= OK then return; end if;
      if not Has_Field (Parsed, "description") then Status := Invalid_Input; return; end if;
      declare F : Field renames Parsed.Fields (Find (Parsed, "description")); E : Natural := F.First; begin
         while E < F.Last and then Char (Raw, E) /= ASCII.LF loop
            exit when Char (Raw, E) not in ' ' | ASCII.HT | ASCII.CR; E := E + 1;
         end loop;
         if E = F.Last or else Char (Raw, E) = ASCII.LF then Status := Invalid_Input; return; end if;
      end;
      Flag ("essential", Candidate.Essential); if Status /= OK then return; end if;
      Flag ("protected", Candidate.Protected_Package); if Status /= OK then return; end if;
      if Has_Field (Parsed, "multi-arch") then
         Get ("multi-arch", Text); if Status /= OK then return; end if;
         declare Mode : constant String := MC_Text.Image (Text); begin
            if Mode = "no" then Candidate.Multi := Pkg_Deb_Semantics.No;
            elsif Mode = "same" then Candidate.Multi := Pkg_Deb_Semantics.Same;
            elsif Mode = "foreign" then Candidate.Multi := Pkg_Deb_Semantics.Foreign;
            elsif Mode = "allowed" then Candidate.Multi := Pkg_Deb_Semantics.Allowed;
            else Status := Invalid_Input; return; end if;
         end;
      end if;
      if Candidate.Multi = Pkg_Deb_Semantics.Same and then MC_Text.Image (Candidate.Architecture) = "all" then
         Status := Invalid_Input; return;
      end if;
      Candidate.Source_Name := Candidate.Name; Candidate.Source_Version := Candidate.Version;
      if Has_Field (Parsed, "source") then
         Get ("source", Text); if Status /= OK then return; end if;
         declare S : constant String := MC_Text.Image (Text); P : Natural := 1; Last : Natural; begin
            while P <= S'Last and then not White (S (P)) loop P := P + 1; end loop;
            if not Package_Name (S (1 .. P - 1)) then Status := Invalid_Input; return; end if;
            MC_Text.Set (Candidate.Source_Name, S (1 .. P - 1), Status); if Status /= OK then return; end if;
            while P <= S'Last and then White (S (P)) loop P := P + 1; end loop;
            if P <= S'Last then
               if S (P) /= '(' or else S (S'Last) /= ')' then Status := Invalid_Input; return; end if;
               P := P + 1; Last := S'Last - 1;
               if not Pkg_Deb_Versions.Valid (S (P .. Last)) then Status := Invalid_Input; return; end if;
               MC_Text.Set (Candidate.Source_Version, S (P .. Last), Status); if Status /= OK then return; end if;
            end if;
         end;
      end if;
      if Has_Field (Parsed, "installed-size") then
         Get ("installed-size", Text); if Status /= OK then return; end if;
         for C of MC_Text.Image (Text) loop
            if C not in '0' .. '9' then Status := Invalid_Input; return; end if;
            declare Digit : constant Counter := Character'Pos (C) - Character'Pos ('0'); begin
               if Candidate.Installed_Size_KiB > (Counter'Last - Digit) / 10 then Status := Exhausted; return; end if;
               Candidate.Installed_Size_KiB := Candidate.Installed_Size_KiB * 10 + Digit;
            end;
         end loop;
         Candidate.Has_Installed_Size := True;
      end if;
      Result := Candidate; Status := OK;
   exception when others => Result := (others => <>); Status := Invalid_Input;
   end Check_Identity;
end Pkg_Deb_Fields;
