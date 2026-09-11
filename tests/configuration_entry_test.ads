-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_Store;
package Configuration_Entry_Test is
   procedure Run (Store : in out MC_Store.Store; Root_FD : Integer;
      Observation : Digest; Path, Media_Path : String; Deadline : Counter);
end Configuration_Entry_Test;
