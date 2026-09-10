-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Text; with MC_Command;
package MC_Tools with SPARK_Mode => Off is
   type Tool is record Path : MC_Text.Value; Content : Digest := Zero_Digest; end record;
   procedure Set_Argument(C : in out MC_Command.Invocation; Text : String; Status : out Outcome);
   procedure Invoke(T : Tool; Arguments : MC_Command.Argument_Array; Count : Natural;
      Deadline : Counter; Mutation : Boolean; Result : out MC_Command.Result; Status : out Outcome);
   procedure Load(Directory, Name : String; T : out Tool; Status : out Outcome);
   -- Protected local '<name>.tool': first line absolute ELF path, second line
   -- SHA256 hex. No third line. Provisioned by an administrator, never a request.
end MC_Tools;
