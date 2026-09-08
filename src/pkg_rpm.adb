-- SPDX-License-Identifier: MIT
with MC_Codec;
package body Pkg_RPM with SPARK_Mode is
   use type Byte; use type Word;
   function Fits (Data : Bytes; Offset, Count : Natural) return Boolean is
     (Offset <= Data'Length and then Count <= Data'Length - Offset);
   function Is_Hook (Tag : Word) return Boolean is
     (Tag in 1023 .. 1026 or else Tag = 1079 or else Tag = 1065
      or else Tag in 1085 .. 1088 or else Tag = 1091 or else Tag = 1092
      or else Tag in 1151 .. 1154 or else Tag in 5020 .. 5027
      or else Tag in 5066 .. 5068 or else Tag in 5076 .. 5078
      or else Tag in 5103 .. 5108);
   function Find (Info : Metadata; Tag : Word) return Natural is
   begin
      for J in 1 .. Info.Entry_Count loop
         if Info.Entries (J).Tag = Tag then return J; end if;
      end loop;
      return 0;
   end Find;
   procedure Read_Header
     (Data : Bytes; Start : Natural; Entries : out Entry_Array;
      Count : out Natural; Next : out Natural; Status : out Outcome)
     with Pre => Data'First = 1 and then Data'Length <= 67_108_864,
          Post => Count <= Max_Entries and then
            (if Status = OK then Next <= Data'Length)
   is
      N, Store_Size, Store_Base, Index_Base, Offset, Items, Kind : Natural;
      Raw_N, Raw_Size, Raw_Offset, Raw_Items, Raw_Kind : Word;
      Width, Span, Cursor, Found_Strings : Natural;
      Scan_Budget : Natural := Max_Header_Bytes * 2;
   begin
      Entries := (others => (others => <>)); Count := 0; Next := Start;
      Status := Invalid_Input;
      if not Fits (Data, Start, 16) then return; end if;
      if Data (Start + 1 .. Start + 4) /= Bytes'(16#8E#,16#AD#,16#E8#,1)
        or else not Is_Zero (Data (Start + 5 .. Start + 8))
      then return; end if;
      Raw_N := MC_Codec.U32 (Data, Start + 9);
      Raw_Size := MC_Codec.U32 (Data, Start + 13);
      if Raw_N > Word (Max_Entries) or else Raw_Size > Word (Max_Header_Bytes) then
         Status := Exhausted; return;
      end if;
      N := Natural (Raw_N); Store_Size := Natural (Raw_Size);
      if not Fits (Data, Start, 16 + N * 16) then return; end if;
      Store_Base := Start + 16 + N * 16;
      if not Fits (Data, Store_Base, Store_Size) then return; end if;
      for J in 1 .. N loop
         Index_Base := Start + 16 + (J - 1) * 16;
         Entries (J).Tag := MC_Codec.U32 (Data, Index_Base + 1);
         Raw_Kind := MC_Codec.U32 (Data, Index_Base + 5);
         Raw_Offset := MC_Codec.U32 (Data, Index_Base + 9);
         Raw_Items := MC_Codec.U32 (Data, Index_Base + 13);
         if Raw_Kind > 9 or else Raw_Offset > Word (Store_Size)
           or else Raw_Items > Word (Max_Header_Bytes)
         then return; end if;
         Kind := Natural (Raw_Kind); Offset := Natural (Raw_Offset);
         Items := Natural (Raw_Items); Span := 0;
         for Previous in 1 .. J - 1 loop
            if Entries (Previous).Tag = Entries (J).Tag then return; end if;
         end loop;
         case Kind is
            when 0 =>
               if Items /= 0 then return; end if;
            when 1 | 2 | 3 | 4 | 5 | 7 =>
               case Kind is
                  when 3 => Width := 2;
                  when 4 => Width := 4;
                  when 5 => Width := 8;
                  when others => Width := 1;
               end case;
               if Offset mod Width /= 0
                 or else Items > (Store_Size - Offset) / Width
               then return; end if;
               Span := Items * Width;
            when 6 | 8 | 9 =>
               if Kind = 6 and then Items /= 1 then return; end if;
               if Items > Store_Size - Offset then return; end if;
               Cursor := Offset; Found_Strings := 0;
               while Found_Strings < Items loop
                  pragma Loop_Invariant (Cursor in Offset .. Store_Size);
                  if Cursor = Store_Size then return; end if;
                  if Scan_Budget = 0 then Status := Exhausted; return; end if;
                  Scan_Budget := Scan_Budget - 1;
                  if Data (Store_Base + Cursor + 1) = 0 then
                     Found_Strings := Found_Strings + 1;
                  end if;
                  Cursor := Cursor + 1;
               end loop;
               Span := Cursor - Offset;
            when others => return;
         end case;
         Entries (J).Data_Type := Kind;
         Entries (J).Data_Offset := Store_Base + Offset;
         Entries (J).Item_Count := Items;
         Entries (J).Span := Span;
      end loop;
      Count := N; Next := Store_Base + Store_Size; Status := OK;
   end Read_Header;
   procedure Inspect (Data : Bytes; Info : out Metadata; Status : out Outcome) is
      Signature_Entries : Entry_Array;
      Signature_Count : Natural;
      Header_End, Main_Start, Main_End, N : Natural;
      Step_Status : Outcome;
      Required : constant array (Positive range 1 .. 5) of Word :=
        (1000, 1001, 1002, 1021, 1022);
      Found : Natural;
   begin
      Info := (others => <>); Status := Invalid_Input;
      if Data'First /= 1 or else Data'Length < 112 or else Data'Length > 67_108_864 then return; end if;
      if Data (1 .. 4) /= Bytes'(16#ED#,16#AB#,16#EE#,16#DB#)
        or else (Data (5) /= 3 and then Data (5) /= 4) or else Data (6) /= 0
        or else MC_Codec.U16 (Data, 7) > 1
        or else MC_Codec.U16 (Data, 79) /= 5
        or else not Is_Zero (Data (81 .. 96))
      then return; end if;
      Info.Is_Source := MC_Codec.U16 (Data, 7) = 1;
      Read_Header (Data, 96, Signature_Entries, Signature_Count, Header_End, Step_Status);
      if Step_Status /= OK then Status := Step_Status; return; end if;
      Main_Start := Header_End + ((8 - Header_End mod 8) mod 8);
      if Main_Start > Data'Length then return; end if;
      for J in Header_End + 1 .. Main_Start loop
         if Data (J) /= 0 then return; end if;
      end loop;
      for J in 1 .. Signature_Count loop
         if Signature_Entries (J).Tag in 267 | 268 | 259 | 262 then
            Info.Has_Signature_Tag := True;
         end if;
      end loop;
      Read_Header (Data, Main_Start, Info.Entries, N, Main_End, Step_Status);
      if Step_Status /= OK then Status := Step_Status; return; end if;
      Info.Entry_Count := N;
      Info.Payload_Offset := Main_End;
      for J in 1 .. N loop
         if Is_Hook (Info.Entries (J).Tag) then Info.Has_Executable_Hooks := True; end if;
      end loop;
      for Tag of Required loop
         Found := Find (Info, Tag);
         if Found = 0 then return; end if;
         if Info.Entries (Found).Data_Type /= 6
           or else Info.Entries (Found).Span <= 1
         then return; end if;
      end loop;
      Status := OK;
   end Inspect;
end Pkg_RPM;
