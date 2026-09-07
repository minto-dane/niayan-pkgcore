-- SPDX-License-Identifier: MIT
with Ada.Streams.Stream_IO;
package body MC_File_IO with SPARK_Mode => Off is
   package IO renames Ada.Streams.Stream_IO;
   use type IO.Count;
   use type Ada.Streams.Stream_Element_Offset;
   function Read_File (Path : String; Limit : Positive := 16_777_216) return Bytes is
      F : IO.File_Type;
      N : IO.Count;
      Buffer : Ada.Streams.Stream_Element_Array (1..4_096);
      Last : Ada.Streams.Stream_Element_Offset;
      Done, Want : Natural := 0;
   begin
      if Limit > 67_108_864 then raise File_Error with "read limit exceeds policy"; end if;
      IO.Open(F,IO.In_File,Path);
      N := IO.Size(F);
      if N > IO.Count(Limit) then IO.Close(F); raise File_Error with "input too large"; end if;
      return Result : Bytes(1..Natural(N)) do
         while Done < Result'Length loop
            Want := Natural'Min(4_096,Result'Length-Done);
            IO.Read(F,Buffer(1..Ada.Streams.Stream_Element_Offset(Want)),Last);
            if Last /= Ada.Streams.Stream_Element_Offset(Want) then
               raise File_Error with "input truncated during read";
            end if;
            for J in 1..Want loop
               Result(Done+J) := Byte(Buffer(Ada.Streams.Stream_Element_Offset(J)));
            end loop;
            Done := Done+Want;
         end loop;
         if not IO.End_Of_File(F) then raise File_Error with "input grew during read"; end if;
         IO.Close(F);
      end return;
   exception
      when others =>
         if IO.Is_Open(F) then IO.Close(F); end if;
         raise;
   end Read_File;
   function Read_Text (Path : String; Limit : Positive := 8_192) return String is
      B : constant Bytes := Read_File(Path,Limit);
      S : String(1..B'Length);
   begin
      for J in B'Range loop S(J) := Character'Val(B(J)); end loop;
      return S;
   end Read_Text;
end MC_File_IO;
