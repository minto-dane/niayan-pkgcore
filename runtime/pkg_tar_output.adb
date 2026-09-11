-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Containers.Indefinite_Ordered_Maps; with Ada.Strings.Fixed;
with Ada.Unchecked_Deallocation; with Interfaces;
with MC_Store;
package body Pkg_Tar_Output with SPARK_Mode => Off is
   package T renames Pkg_Tar_Framing;
   package Fields is new Ada.Containers.Indefinite_Ordered_Maps (String, String);
   use type Word; use type Interfaces.Integer_64;
   type Data is record
      Values : Fields.Map;
      Mode : Word := 0;
      Length : Natural := 0;
   end record;
   procedure Free is new Ada.Unchecked_Deallocation (Data, Data_Access);
   procedure Clear (Value : in out Header) is
   begin Free (Value.State); end Clear;
   overriding procedure Finalize (Value : in out Header) is
   begin Clear (Value); end Finalize;
   function Decimal (Value : Counter) return String is
     (Ada.Strings.Fixed.Trim (Counter'Image (Value), Ada.Strings.Both));
   function Record_Size (Key, Value : String) return Natural is
      Base : constant Natural := Key'Length + Value'Length + 3; Size : Natural := Base + 1; Next : Natural;
   begin
      loop Next := Base + Decimal (Counter (Size))'Length; exit when Next = Size; Size := Next; end loop;
      return Size;
   end Record_Size;
   procedure Insert (Value : in out Header; Key, Text : String; Status : out Outcome) is
      Size : Natural;
   begin
      Status := Invalid_Input;
      if Value.State.Values.Contains (Key) then Clear (Value); return; end if;
      if Key'Length > T.Max_Key or else Text'Length > T.Max_Extension then Status := Exhausted; Clear (Value); return; end if;
      Size := Record_Size (Key, Text);
      if Size > T.Max_Extension - Value.State.Length then Status := Exhausted; Clear (Value); return; end if;
      Value.State.Values.Insert (Key, Text); Value.State.Length := Value.State.Length + Size; Status := OK;
   end Insert;
   function Clock_Text (Clock : T.Timestamp) return String is
      Sec : Interfaces.Integer_64 := Clock.Seconds;
      Nsec : Natural := Clock.Nanoseconds;
      Fraction : String (1 .. 9); Last : Natural := 9;
      function Magnitude (Value : Interfaces.Integer_64) return String is
         Text : constant String := Interfaces.Integer_64'Image (Value);
      begin return Text (Text'First + 1 .. Text'Last); end Magnitude;
   begin
      -- POSIX timespec uses floor seconds and a nonnegative fraction. Decimal
      -- negative timestamps instead subtract that fraction from the magnitude.
      if Sec < 0 and then Nsec /= 0 then Sec := Sec + 1; Nsec := 1_000_000_000 - Nsec; end if;
      for I in reverse Fraction'Range loop Fraction (I) := Character'Val (48 + Nsec mod 10); Nsec := Nsec / 10; end loop;
      while Last > 0 and then Fraction (Last) = '0' loop Last := Last - 1; end loop;
      return (if Clock.Seconds < 0 then "-" else "") & Magnitude (Sec)
         & (if Last = 0 then "" else "." & Fraction (1 .. Last));
   end Clock_Text;
   procedure Start (Value : in out Header; Path : String; Mode, UID, GID : Word;
      Size : Counter; Clocks : T.Clock_Array; Status : out Outcome) is
      First : Natural := Path'First;
      Interrupted : exception;
      procedure Add (Key, Text : String) is
      begin Insert (Value, Key, Text, Status); if Status /= OK then raise Interrupted; end if; end Add;
   begin
      Clear (Value); Status := Invalid_Input;
      if Path'Length not in 1 .. 4_096 or else Path (Path'First) = '/' or else Path (Path'Last) = '/'
         or else Mode > 8#7777# or else Size > MC_Store.Max_Object_Size or else not Clocks (1).Present then return; end if;
      for I in Path'Range loop
         if Path (I) = ASCII.NUL then return; end if;
         if Path (I) = '/' then
            if I = First or else I - First > 255 or else Path (First .. I - 1) in "." | ".." then return; end if;
            First := I + 1;
         end if;
      end loop;
      if Path'Last - First + 1 > 255 or else Path (First .. Path'Last) in "." | ".." then return; end if;
      Value.State := new Data; Value.State.Mode := Mode;
      Add ("hdrcharset", "BINARY"); Add ("path", Path); Add ("size", Decimal (Size));
      Add ("uid", Decimal (Counter (UID))); Add ("gid", Decimal (Counter (GID)));
      for I in Clocks'Range loop
         if Clocks (I).Present then
            Add ((case I is when 1 => "mtime", when 2 => "atime", when 3 => "ctime", when 4 => "LIBARCHIVE.creationtime"), Clock_Text (Clocks (I)));
         end if;
      end loop;
   exception
      when Interrupted => Clear (Value);
      when Storage_Error => Clear (Value); Status := Exhausted;
      when others => Clear (Value); Status := Invalid_Input;
   end Start;
   procedure Add_Extension (Value : in out Header; Key : String; Data : Bytes; Status : out Outcome) is
   begin
      Status := Invalid_Input; if Value.State = null then return; end if;
      if not (Key in "SCHILY.fflags" | "SCHILY.acl.access" | "SCHILY.acl.default"
         or else (Key'Length > 13 and then Key (Key'First .. Key'First + 12) = "SCHILY.xattr.")
         or else (Key'Length > 17 and then Key (Key'First .. Key'First + 16) = "LIBARCHIVE.xattr.")) then Clear (Value); return; end if;
      for C of Key loop if C not in '!' .. '~' or else C = '=' then Clear (Value); return; end if; end loop;
      if Key'Length > T.Max_Key or else Data'Length > T.Max_Extension then Status := Exhausted; Clear (Value); return; end if;
      declare Text : String (1 .. Data'Length); begin
         for I in Text'Range loop Text (I) := Character'Val (Data (Data'First + (I - 1))); end loop;
         Insert (Value, Key, Text, Status);
      end;
   exception
      when Storage_Error => Clear (Value); Status := Exhausted;
      when others => Clear (Value); Status := Invalid_Input;
   end Add_Extension;
   procedure Add_Xattr (Value : in out Header; Name : String; Data : Bytes; Status : out Outcome) is
      Hex : constant String := "0123456789ABCDEF";
      Alphabet : constant String := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      Encoded_Name : String (1 .. 3 * 255); Name_Used : Natural := 0;
   begin
      Status := Invalid_Input; if Value.State = null then return; end if;
      if Name'Length = 0 then Clear (Value); return; end if;
      if Name'Length > 255 or else Data'Length > 65_536 then Clear (Value); Status := Exhausted; return; end if;
      for C of Name loop
         if C = ASCII.NUL then Clear (Value); Status := Invalid_Input; return; end if;
         if C in 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_' | '.' | '-' then
            Name_Used := Name_Used + 1; Encoded_Name (Name_Used) := C;
         else
            Encoded_Name (Name_Used + 1 .. Name_Used + 3) := '%' & Hex (Character'Pos (C) / 16 + 1) & Hex (Character'Pos (C) mod 16 + 1);
            Name_Used := Name_Used + 3;
         end if;
      end loop;
      declare Encoded : String (1 .. 4 * ((Data'Length + 2) / 3)); Used, Offset : Natural := 0;
         A, B, C, Take : Natural;
         procedure Emit (Number : Natural) is
         begin Used := Used + 1; Encoded (Used) := Alphabet (Number + 1); end Emit;
      begin
         while Offset < Data'Length loop
            Take := Natural'Min (3, Data'Length - Offset);
            A := Natural (Data (Data'First + Offset));
            B := (if Take >= 2 then Natural (Data (Data'First + Offset + 1)) else 0);
            C := (if Take = 3 then Natural (Data (Data'First + Offset + 2)) else 0);
            Emit (A / 4); Emit ((A mod 4) * 16 + B / 16);
            if Take >= 2 then Emit ((B mod 16) * 4 + C / 64); end if;
            if Take = 3 then Emit (C mod 64); end if;
            Offset := Offset + Take;
         end loop;
         Insert (Value, "LIBARCHIVE.xattr." & Encoded_Name (1 .. Name_Used), Encoded (1 .. Used), Status);
      end;
   exception
      when Storage_Error => Clear (Value); Status := Exhausted;
      when others => Clear (Value); Status := Invalid_Input;
   end Add_Xattr;
   procedure Finish (Value : in out Header; Output : out Bytes; Used : out Natural; Status : out Outcome) is
      Offset : Natural := 0; Padded : Natural;
      procedure Text (At_Byte : Natural; Value : String) is
      begin
         for I in Value'Range loop Output (Output'First + At_Byte + (I - Value'First)) := Character'Pos (Value (I)); end loop;
      end Text;
      procedure Octal (At_Byte, Length : Natural; Value : Counter) is
         N : Counter := Value;
      begin
         for I in reverse 0 .. Length - 2 loop
            Output (Output'First + At_Byte + I) := Byte (48 + N mod 8); N := N / 8;
         end loop;
         if N /= 0 then raise Constraint_Error; end if;
      end Octal;
      procedure Block (At_Byte : Natural; Name : String; Kind : Character; Size : Natural; Mode : Word) is
         Sum : Counter := 0;
      begin
         Text (At_Byte, Name); Octal (At_Byte + 100, 8, Counter (Mode));
         Octal (At_Byte + 108, 8, 0); Octal (At_Byte + 116, 8, 0);
         Octal (At_Byte + 124, 12, Counter (Size)); Octal (At_Byte + 136, 12, 0);
         Text (At_Byte + 148, "        "); Text (At_Byte + 156, String'(1 => Kind));
         Text (At_Byte + 257, "ustar"); Text (At_Byte + 263, "00");
         for I in 0 .. 511 loop Sum := Sum + Counter (Output (Output'First + At_Byte + I)); end loop;
         Output (Output'First + At_Byte + 154) := 0;
         Octal (At_Byte + 148, 7, Sum);
      end Block;
   begin
      Output := (others => 0); Used := 0; Status := Invalid_Input;
      if Value.State = null then return; end if;
      Padded := ((Value.State.Length + 511) / 512) * 512;
      if Output'Length < Padded + 1_024 then Status := Exhausted; Clear (Value); return; end if;
      Block (0, "PaxHeaders/configuration", 'x', Value.State.Length, 8#600#); Offset := 512;
      for Cursor in Value.State.Values.Iterate loop
         declare Key : constant String := Fields.Key (Cursor); Data : constant String := Fields.Element (Cursor);
            Record_Text : constant String := Decimal (Counter (Record_Size (Key, Data))) & " " & Key & "=" & Data & ASCII.LF;
         begin Text (Offset, Record_Text); Offset := Offset + Record_Text'Length; end;
      end loop;
      Block (512 + Padded, "configuration", '0', 0, Value.State.Mode);
      Used := Padded + 1_024; Clear (Value); Status := OK;
   exception
      when others => Clear (Value); Output := (others => 0); Used := 0; Status := Invalid_Input;
   end Finish;
end Pkg_Tar_Output;
