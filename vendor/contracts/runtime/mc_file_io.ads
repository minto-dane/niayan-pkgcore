-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package MC_File_IO with SPARK_Mode => Off is
   File_Error : exception;
   function Read_File (Path : String; Limit : Positive := 16_777_216) return Bytes;
   function Read_Text (Path : String; Limit : Positive := 8_192) return String;
   -- Inspection/qualification I/O only. This is NOT an immutable-descriptor
   -- handoff for privileged installation, and must not be used as one.
end MC_File_IO;
