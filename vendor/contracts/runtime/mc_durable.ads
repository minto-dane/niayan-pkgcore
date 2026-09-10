-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package MC_Durable with SPARK_Mode => Off is
   type Directory_Handle is limited private;
   type File_Handle is limited private;
   procedure Open_Private_Directory
     (Path : String; Handle : in out Directory_Handle; Status : out Outcome);
   procedure Open_Journal
     (Directory : Directory_Handle; Name : String;
      Handle : in out File_Handle; Status : out Outcome);
   procedure Open_Readonly
     (Directory : Directory_Handle; Name : String;
      Handle : in out File_Handle; Status : out Outcome);
   procedure Size (Handle : File_Handle; Length : out Counter; Status : out Outcome);
   procedure Read_At
     (Handle : File_Handle; Offset : Counter; Data : out Bytes; Status : out Outcome);
   procedure Append
     (Handle : in out File_Handle; Expected_Size : Counter;
      Data : Bytes; Status : out Outcome);
   procedure Close (Handle : in out File_Handle; Status : out Outcome);
   procedure Close (Handle : in out Directory_Handle; Status : out Outcome);
   -- Linux x86-64 ABI boundary. All path components are opened relative to directory
   -- descriptors with O_NOFOLLOW. Final directory must be owned by euid, mode 0700.
   -- Journals must be regular, private, singly-linked files owned by euid.
   -- Locks are advisory; enforcement of a single writer is a deployment prerequisite.
   -- fsync failures and partial writes poison the handle. No automatic truncation.
private
   type Directory_Handle is limited record
      FD : Integer := -1;
   end record;
   type File_Handle is limited record
      FD : Integer := -1;
      Writable : Boolean := False;
      Poisoned : Boolean := False;
   end record;
end MC_Durable;
