-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Unchecked_Deallocation;
with Ada.Containers.Indefinite_Ordered_Sets;
with MC_Clock;
package body Pkg_Tar_Framing with SPARK_Mode => Off is
   use type Byte;
   use type Interfaces.Integer_64;
   use Ada.Strings.Unbounded;
   function Count (Value : Index) return Natural is (Natural (Value.Frames.Length));
   function At_Index (Value : Index; Position : Positive) return Frame is
     (if Position <= Count (Value) then Value.Frames.Element (Position) else (others => <>));
   function Terminator (Value : Index) return Counter is (Value.End_Offset);
   procedure Scan (File : MC_FS.File; Size, Deadline : Counter;
                   Result : out Index; Status : out Outcome) is
      Candidate : Index;
      Header : Bytes (1 .. 512); Scratch : Bytes (1 .. 65_536);
      Position, Body_Start, Body_Size, Next_Position, Now : Counter := 0;
      Extensions : Counter := 0; Extension_Count : Natural := 0;
      Local_Size : Counter := 0;
      Has_Local_Size, Pending_Local : Boolean := False;
      Seen_Pax, Seen_Name, Seen_Link : Boolean := False;
      Clocks : Clock_Array;
      Flags : Unbounded_String;
      Names : Name_Array;
      Type_Flag : Character;
      type Buffer_Access is access Bytes;
      procedure Free is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
      Extended : Buffer_Access;
      procedure Check_Time is
      begin
         MC_Clock.Boottime_Milliseconds (Now, Status);
         if Status = OK and then Now >= Deadline then Status := Stale; end if;
      end Check_Time;
      procedure Read (At_Byte : Counter; B : out Bytes) is
         Used : Natural;
      begin
         Check_Time; if Status /= OK then return; end if;
         if At_Byte > Size or else Counter (B'Length) > Size - At_Byte then Status := Corrupt; return; end if;
         MC_FS.Read_At (File, At_Byte, B, Used, Status);
         if Status = OK and then Used /= B'Length then Status := Corrupt; end if;
      end Read;
      procedure Number (B : Bytes; Value : out Counter) is
         P : Natural := B'First; Digit : Counter;
      begin
         Value := 0; Status := Corrupt;
         if B (P) = 16#80# then
            P := P + 1;
            while P <= B'Last loop
               if Value > (Counter'Last - Counter (B (P))) / 256 then return; end if;
               Value := Value * 256 + Counter (B (P)); P := P + 1;
            end loop;
         else
            while P <= B'Last and then B (P) = 32 loop P := P + 1; end loop;
            while P <= B'Last and then B (P) in 48 .. 55 loop
               Digit := Counter (B (P) - 48);
               if Value > (Counter'Last - Digit) / 8 then return; end if;
               Value := Value * 8 + Digit; P := P + 1;
            end loop;
            while P <= B'Last loop
               if B (P) not in 0 | 32 then return; end if; P := P + 1;
            end loop;
         end if;
         Status := OK;
      end Number;
      procedure Signed_Number (B : Bytes) is
         Value : Counter; Inverted : Bytes (B'Range);
      begin
         if B (B'First) = 16#FF# then
            -- Negative GNU base256: one's complement must fit positive int64.
            for I in B'Range loop Inverted (I) := 255 - B (I); end loop;
            Inverted (B'First) := 16#80#; Number (Inverted, Value);
         else Number (B, Value); end if;
      end Signed_Number;
      function All_Zero (B : Bytes) return Boolean is
      begin for C of B loop if C /= 0 then return False; end if; end loop; return True; end All_Zero;
      procedure Zeroes (First, Last : Counter) is
         P : Counter := First; N : Natural;
      begin
         while P < Last loop
            N := Natural (Counter'Min (Counter (Scratch'Length), Last - P));
            Read (P, Scratch (1 .. N)); if Status /= OK then return; end if;
            if not All_Zero (Scratch (1 .. N)) then Status := Corrupt; return; end if;
            P := P + Counter (N);
         end loop;
      end Zeroes;
      procedure Pax (B : Bytes) is
         package Keys is new Ada.Containers.Indefinite_Ordered_Sets (String);
         Seen_Keys : Keys.Set;
         P : Natural := B'First; Start, Length, Boundary, Key_Start, Equal_At : Natural;
         Value : Counter; Digit : Natural;
         function Text (First, Last : Natural) return String is
            S : String (1 .. Last - First + 1);
         begin
            for I in S'Range loop S (I) := Character'Val (B (First + I - 1)); end loop; return S;
         end Text;
         function Decimal (First, Last : Natural; Ceiling : Counter) return Boolean is
            N : Counter := 0; D : Counter;
         begin
            if First > Last then return False; end if;
            for I in First .. Last loop
               if B (I) not in 48 .. 57 then return False; end if;
               D := Counter (B (I) - 48);
               if D > Ceiling or else N > (Ceiling - D) / 10 then return False; end if;
               N := N * 10 + D;
            end loop;
            return True;
         end Decimal;
         function Parse_Clock (First, Last : Natural; Value : out Timestamp) return Boolean is
            P : Natural := First; Dot : Natural := Last + 1;
            Negative : Boolean := False; Sec : Interfaces.Integer_64 := 0; Nsec : Natural := 0;
         begin
            Value := (others => <>);
            if P > Last then return False; end if;
            if B (P) = 45 then Negative := True; P := P + 1; end if;
            for I in P .. Last loop if B (I) = 46 then Dot := I; exit; end if; end loop;
            if P >= Dot then return False; end if;
            -- Accumulate negatively to admit the full signed minimum without
            -- an overflowing intermediate positive magnitude.
            for I in P .. Dot - 1 loop
               if B (I) not in 48 .. 57 then return False; end if;
               declare D : constant Interfaces.Integer_64 := Interfaces.Integer_64 (B (I) - 48); begin
                  if Sec < (Interfaces.Integer_64'First + D) / 10 then return False; end if;
                  Sec := Sec * 10 - D;
               end;
            end loop;
            if not Negative and then Sec = Interfaces.Integer_64'First then return False; end if;
            if Dot <= Last then
               if Dot = Last then return False; end if;
               for I in Dot + 1 .. Last loop
                  if B (I) not in 48 .. 57 or else (I - Dot > 9 and then B (I) /= 48) then return False; end if;
                  if I - Dot <= 9 then Nsec := Nsec * 10 + Natural (B (I) - 48); end if;
               end loop;
               for I in Last - Dot + 1 .. 9 loop Nsec := Nsec * 10; end loop;
            end if;
            if Negative then
               if Nsec /= 0 then
                  if Sec = Interfaces.Integer_64'First then return False; end if;
                  Sec := Sec - 1; Nsec := 1_000_000_000 - Nsec;
               end if;
            else Sec := -Sec; end if;
            Value := (True, Sec, Nsec);
            return True;
         end Parse_Clock;
         function Valid_ACL (First, Last : Natural) return Boolean is
            package Keys is new Ada.Containers.Indefinite_Ordered_Sets (String);
            Seen : Keys.Set;
            Start : Natural := First; Colon : array (1 .. 3) of Natural;
            N : Natural; Owner, Group, Other, Mask, Named : Boolean := False;
         begin
            if First > Last then return False; end if;
            for Stop in First .. Last + 1 loop
               if Stop = Last + 1 or else B (Stop) = 44 then
                  if Stop = Start then return False; end if;
                  N := 0;
                  for I in Start .. Stop - 1 loop
                     if B (I) = 58 then
                        if N = 3 then return False; end if;
                        N := N + 1; Colon (N) := I;
                     elsif B (I) = 0 then return False; end if;
                  end loop;
                  if N < 2 then return False; end if;
                  declare
                     Kind : constant String := Text (Start, Colon (1) - 1);
                     Name : constant String := Text (Colon (1) + 1, Colon (2) - 1);
                     Perm_Last : constant Natural := (if N = 3 then Colon (3) - 1 else Stop - 1);
                     Identity : constant String := Kind & ":" & Name;
                  begin
                     if Kind not in "user" | "group" | "mask" | "other" or else Seen.Contains (Identity)
                        or else Perm_Last - Colon (2) /= 3 then return False; end if;
                     Seen.Insert (Identity);
                     if B (Colon (2) + 1) not in 114 | 45 or else B (Colon (2) + 2) not in 119 | 45
                        or else B (Colon (2) + 3) not in 120 | 45 then return False; end if;
                     if Kind in "mask" | "other" and then Name'Length /= 0 then return False; end if;
                     if Name'Length = 0 then
                        if N = 3 then return False; end if;
                        if Kind = "user" then Owner := True;
                        elsif Kind = "group" then Group := True;
                        elsif Kind = "other" then Other := True;
                        else Mask := True; end if;
                     else
                        Named := True;
                        -- The pinned ACL reader normalizes Unicode names.
                        -- Keep this ACL profile ASCII until native name/ID
                        -- decoding can preserve every original byte.
                        for C of Name loop if C not in '!' .. '~' then return False; end if; end loop;
                        if N = 3 and then not Decimal (Colon (3) + 1, Stop - 1, 16#7FFF_FFFF#) then return False; end if;
                        declare Numeric : Boolean := True; begin
                           for C of Name loop if C not in '0' .. '9' then Numeric := False; end if; end loop;
                           if Numeric and then not Decimal (Colon (1) + 1, Colon (2) - 1, 16#7FFF_FFFF#) then return False; end if;
                        end;
                     end if;
                  end;
                  Start := Stop + 1;
               end if;
            end loop;
            return Owner and then Group and then Other and then (not Named or else Mask);
         end Valid_ACL;
         function Encoded_Name (Key : String) return Boolean is
            P : Positive := Key'First; Count : Natural := 0; Code : Natural;
            function Digit (C : Character) return Natural is
              (case C is when '0' .. '9' => Character'Pos (C) - 48,
               when 'A' .. 'F' => Character'Pos (C) - 55,
               when 'a' .. 'f' => Character'Pos (C) - 87, when others => 16);
         begin
            while P <= Key'Last loop
               Code := Character'Pos (Key (P));
               if Key (P) = '%' then
                  if Key'Last - P < 2 or else Digit (Key (P + 1)) > 15 or else Digit (Key (P + 2)) > 15 then return False; end if;
                  Code := Digit (Key (P + 1)) * 16 + Digit (Key (P + 2)); P := P + 2;
               end if;
               if Code = 0 or else Count = 255 then return False; end if;
               Count := Count + 1; P := P + 1;
            end loop;
            return Count > 0;
         end Encoded_Name;
         function Base64_Value (First, Last : Natural) return Boolean is
            Length : constant Natural := Last - First + 1; Raw_Length : Natural := Length;
            Padding : Natural := 0;
            function Code (C : Byte) return Natural is
              (case C is when 65 .. 90 => Natural (C) - 65, when 97 .. 122 => Natural (C) - 71,
               when 48 .. 57 => Natural (C) + 4, when 43 => 62, when 47 => 63, when others => 64);
         begin
            if Length > 87_384 then return False; end if;
            while Raw_Length > 0 and then B (First + Raw_Length - 1) = 61 loop
               Raw_Length := Raw_Length - 1; Padding := Padding + 1;
               if Padding > 2 then return False; end if;
            end loop;
            if Raw_Length mod 4 = 1 or else (Raw_Length * 6) / 8 > 65_536 then return False; end if;
            if Padding /= 0 and then (Length mod 4 /= 0 or else Raw_Length mod 4 = 0
               or else Padding /= 4 - Raw_Length mod 4) then return False; end if;
            for I in 0 .. Raw_Length - 1 loop if Code (B (First + I)) > 63 then return False; end if; end loop;
            if Raw_Length mod 4 = 2 then return Code (B (First + Raw_Length - 1)) mod 16 = 0;
            elsif Raw_Length mod 4 = 3 then return Code (B (First + Raw_Length - 1)) mod 4 = 0;
            else return True; end if;
         end Base64_Value;
      begin
         Status := Corrupt;
         while P <= B'Last loop
            Start := P; Length := 0;
            while P <= B'Last and then B (P) in 48 .. 57 loop
               Digit := Natural (B (P) - 48);
               if Length > (Max_Extension - Digit) / 10 then return; end if;
               Length := Length * 10 + Digit; P := P + 1;
            end loop;
            if P = Start or else P > B'Last or else B (P) /= 32
               or else Length > B'Last - Start + 1 or else Length < P - Start + 4 then return; end if;
            Boundary := Start + Length - 1;
            if B (Boundary) /= 10 then return; end if;
            P := P + 1; Key_Start := P;
            while P < Boundary and then B (P) /= 61 loop
               if B (P) not in 33 .. 126 then return; end if; P := P + 1;
            end loop;
            if P = Key_Start or else P = Boundary or else P - Key_Start > Max_Key then return; end if;
            Equal_At := P;
            declare Key : constant String := Text (Key_Start, Equal_At - 1); begin
               if Seen_Keys.Contains (Key) then Status := Unsupported; return; end if;
               Seen_Keys.Insert (Key);
               if Key = "hdrcharset" then
                  if Text (Equal_At + 1, Boundary - 1) /= "BINARY" then Status := Unsupported; return; end if;
               elsif Key = "size" then
                  if Equal_At + 1 = Boundary then Status := Unsupported; return; end if;
                  Value := 0;
                  for I in Equal_At + 1 .. Boundary - 1 loop
                     if B (I) not in 48 .. 57 or else Value > (Size - Counter (B (I) - 48)) / 10 then Status := Corrupt; return; end if;
                     Value := Value * 10 + Counter (B (I) - 48);
                  end loop;
                  Local_Size := Value; Has_Local_Size := True;
               elsif Key in "uid" | "gid" then
                  if not Decimal (Equal_At + 1, Boundary - 1, Counter (Word'Last)) then Status := Unsupported; return; end if;
               elsif Key in "mtime" | "atime" | "ctime" | "LIBARCHIVE.creationtime" then
                  declare Slot : constant Positive := (if Key = "mtime" then 1 elsif Key = "atime" then 2 elsif Key = "ctime" then 3 else 4); begin
                     if not Parse_Clock (Equal_At + 1, Boundary - 1, Clocks (Slot)) then Status := Unsupported; return; end if;
                  end;
               elsif Key = "SCHILY.fflags" then
                  if Boundary - Equal_At - 1 > 4096 then Status := Exhausted; return; end if;
                  for I in Equal_At + 1 .. Boundary - 1 loop if B (I) = 0 then Status := Corrupt; return; end if; end loop;
                  Flags := To_Unbounded_String (Text (Equal_At + 1, Boundary - 1));
               elsif Key in "SCHILY.acl.access" | "SCHILY.acl.default" then
                  if not Valid_ACL (Equal_At + 1, Boundary - 1) then Status := Unsupported; return; end if;
               elsif Key in "path" | "linkpath" | "uname" | "gname"
                  then
                  if Equal_At + 1 = Boundary then Status := Unsupported; return; end if;
                  if Boundary - Equal_At - 1 > 4096 then Status := Exhausted; return; end if;
                  for I in Equal_At + 1 .. Boundary - 1 loop
                     if B (I) = 0 then Status := Corrupt; return; end if;
                  end loop;
                  declare Slot : constant Positive := (if Key = "path" then 1 elsif Key = "linkpath" then 2 elsif Key = "uname" then 3 else 4); begin
                     Names (Slot) := To_Unbounded_String (Text (Equal_At + 1, Boundary - 1));
                  end;
               elsif Key'Length > 13 and then Key (1 .. 13) = "SCHILY.xattr." then null;
               elsif Key'Length > 17 and then Key (1 .. 17) = "LIBARCHIVE.xattr." then
                  if not Encoded_Name (Key (18 .. Key'Last)) or else not Base64_Value (Equal_At + 1, Boundary - 1) then
                     Status := Corrupt; return;
                  end if;
               else Status := Unsupported; return;
               end if;
            end;
            P := Boundary + 1;
         end loop;
         Status := OK;
      end Pax;
   begin
      Result := (others => <>); Status := Corrupt;
      if Size < 1024 or else Size mod 512 /= 0 then return; end if;
      while Position < Size loop
         Read (Position, Header); if Status /= OK then Free (Extended); return; end if;
         if All_Zero (Header) then
            if Size - Position < 1024 or else Pending_Local then Status := Corrupt; return; end if;
            Zeroes (Position + 512, Size); if Status /= OK then return; end if;
            Candidate.End_Offset := Position; Result := Candidate; return;
         end if;
         declare Expected_Checksum, Actual_Checksum, Mode : Counter := 0; begin
            Number (Header (149 .. 156), Expected_Checksum); if Status /= OK then return; end if;
            for I in Header'Range loop
               Actual_Checksum := Actual_Checksum + (if I in 149 .. 156 then 32 else Counter (Header (I)));
            end loop;
            if Actual_Checksum /= Expected_Checksum then Status := Corrupt; return; end if;
            Number (Header (101 .. 108), Mode); if Status /= OK then return; end if;
            if Mode > 8#7777# then Status := Unsupported; return; end if;
         end;
         Number (Header (125 .. 136), Body_Size); if Status /= OK then return; end if;
         declare Numeric : Counter; begin
            Number (Header (109 .. 116), Numeric); if Status /= OK then return; end if;
            if Numeric > Counter (Word'Last) then Status := Unsupported; return; end if;
            Number (Header (117 .. 124), Numeric); if Status /= OK then return; end if;
            if Numeric > Counter (Word'Last) then Status := Unsupported; return; end if;
            Signed_Number (Header (137 .. 148)); if Status /= OK then return; end if;
            if Header (258 .. 262) = Bytes'(117, 115, 116, 97, 114) then
               Number (Header (330 .. 337), Numeric); if Status /= OK then return; end if;
               if Numeric > Counter (Word'Last) then Status := Unsupported; return; end if;
               Number (Header (338 .. 345), Numeric); if Status /= OK then return; end if;
               if Numeric > Counter (Word'Last) then Status := Unsupported; return; end if;
               if Header (263 .. 265) = Bytes'(32, 32, 0) then
                  Signed_Number (Header (346 .. 357)); if Status /= OK then return; end if;
                  Signed_Number (Header (358 .. 369)); if Status /= OK then return; end if;
               end if;
            end if;
         end;
         Type_Flag := Character'Val (Header (157)); Body_Start := Position + 512;
         -- The pinned upstream reader does not apply global PAX attributes.
         -- Refuse this profile until a complete native global layer exists.
         if Type_Flag = 'g' then Status := Unsupported; return; end if;
         if Type_Flag not in 'x' | 'g' | 'L' | 'K' then
            if Has_Local_Size then Body_Size := Local_Size; end if;
         end if;
         if Body_Size > Size - Body_Start then Status := Corrupt; return; end if;
         Next_Position := Body_Start + Body_Size;
         if Body_Size mod 512 /= 0 then Next_Position := Next_Position + 512 - Body_Size mod 512; end if;
         if Next_Position > Size then Status := Corrupt; return; end if;
         Zeroes (Body_Start + Body_Size, Next_Position); if Status /= OK then return; end if;
         if Type_Flag in 'x' | 'g' | 'L' | 'K' then
            -- Nested/repeated extension headers have reader-dependent override
            -- order. Accept at most one of each local extension per entry.
            if (Type_Flag = 'x' and then Seen_Pax) or else (Type_Flag = 'L' and then Seen_Name)
               or else (Type_Flag = 'K' and then Seen_Link) then Status := Unsupported; return; end if;
            if (Type_Flag = 'x' and then (Seen_Name or else Seen_Link))
               or else (Type_Flag in 'L' | 'K' and then Seen_Pax) then Status := Unsupported; return; end if;
            if Type_Flag = 'x' then Seen_Pax := True;
            elsif Type_Flag = 'L' then Seen_Name := True;
            elsif Type_Flag = 'K' then Seen_Link := True; end if;
            if Body_Size = 0 then Status := Corrupt; return; end if;
            if Body_Size > Max_Extension or else Body_Size > Max_Extension_Total - Extensions
               or else Extension_Count = Max_Entries * 2 then Status := Exhausted; return; end if;
            Extensions := Extensions + Body_Size; Extension_Count := Extension_Count + 1;
            Extended := new Bytes (1 .. Natural (Body_Size));
            Read (Body_Start, Extended.all); if Status /= OK then Free (Extended); return; end if;
            if Type_Flag = 'x' then Pax (Extended.all);
            else
               if Extended (Extended'Last) /= 0 then Status := Corrupt;
               else
                  for I in Extended'First .. Extended'Last - 1 loop
                     if Extended (I) = 0 then Status := Corrupt; exit; end if;
                  end loop;
               end if;
            end if;
            Free (Extended); if Status /= OK then return; end if;
            if Type_Flag /= 'g' then Pending_Local := True; end if;
         else
            if Type_Flag not in ASCII.NUL | '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' then Status := Unsupported; return; end if;
            if Type_Flag in '1' .. '6' and then Body_Size /= 0 then Status := Unsupported; return; end if;
            if Count (Candidate) = Max_Entries then Status := Exhausted; return; end if;
            Candidate.Frames.Append (Frame'(Position, Body_Start, Body_Size, Type_Flag, Clocks, Flags, Names));
            Pending_Local := False; Has_Local_Size := False;
            Clocks := (others => <>); Flags := Null_Unbounded_String;
            Names := (others => Null_Unbounded_String);
            Seen_Pax := False; Seen_Name := False; Seen_Link := False;
         end if;
         Position := Next_Position;
      end loop;
      Status := Corrupt;
   exception
      when Storage_Error => Free (Extended); Result := (others => <>); Status := Exhausted;
      when others => Free (Extended); Result := (others => <>); Status := Corrupt;
   end Scan;
end Pkg_Tar_Framing;
