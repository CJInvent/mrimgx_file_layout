"""Bound Dissect reads at VHDX payload boundaries.

Some Dissect releases choose min(requested, sectors_per_block) without
subtracting the starting sector within the block. Such a read can incorrectly
continue into the next physical payload instead of consulting its BAT state.
"""
from dissect.hypervisor.disk.vhdx import VHDX as DissectVHDX


class VHDX(DissectVHDX):
    def read_sectors(self,sector,count):
        chunks=[]
        while count:
            within=sector%self._sectors_per_block
            n=min(count,self._sectors_per_block-within)
            chunks.append(super().read_sectors(sector,n))
            sector+=n;count-=n
        return b''.join(chunks)
