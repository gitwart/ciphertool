# genetic.tcl --
#
#	Library routines for running permutation-based genetic algorithms. 
#
# RCS: @(#) $Id: geneticPerm.tcl,v 1.1 2005/04/20 21:14:07 wart Exp $
#
# Copyright (C) 2005  Mike Thomas <wart@kobold.org>
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

package require cipher
package require Hillclimb

package provide GeneticPerm 1.0

namespace eval GeneticPerm {
    set probability(crossover) 0.7
    set probability(mutate) 0.01
    set mateProc GeneticPerm::mate
}

# GeneticPerm::mutate
#
#	Mutate the current gene sequence by wandering some number of steps away
#	by traveling to neighbor keys.  See Hillclimb::mutate for
#       the actual implementation details.
#
# Arguments:
#
#	gene		The gene sequence to be mutated
#	amount		Amount of mutation to apply, that is, the number
#                       of gene pairs to swap.
#	type		Optional.  Treat the key as belonging to a cipher
#			of this type.  If not supplied, the default
#			neighbor key procedure will be used.
#
# Result:
#	A new gene sequence.

proc GeneticPerm::mutate {gene amount {type {}}} {
    return [Hillclimb::mutate $gene $amount $type]
}

# GeneticPerm::mate
#
#	Mate the fittest members of the gene pool.    Only the top 50% members
#	of the gene pool will mate.  The chance of mating to occur is defined
#	by the GeneticPerm::probability(crossover) variable.  This usually has
#	a value from 0.6 to 1.0.  If mating does not occur between 2 selected
#       members then they are carried through unchanged to the next generation.
#
# Arguments:
#
#	genePool	The gene pool that will mate.
#
# Result:
#	A new gene pool.

proc GeneticPerm::mate {genePool} {
    variable probability
    set poolSize [llength $genePool]

    # Sort the gene pool to find the top 50% fittest members.
    set sortedGenePool [lsort -real -decreasing -command GeneticPerm::geneCompare $genePool]
    set fittestMembers [lrange $sortedGenePool 0 [expr {$poolSize/2-1}]]

    set offspring {}
    for {set i 0} {$i < [llength $fittestMembers]} {incr i} {
        set parent1 [lindex $fittestMembers $i]
        set parent2Index [expr {int(rand() * [llength $fittestMembers])}]
        # No hermaphrodites!
        if {$parent2Index == $i} {
            incr parent2Index
        }
        if {$parent2Index >= [llength $fittestMembers]} {
            set parent2Index 0
        }
        set parent2 [lindex $fittestMembers $parent2Index]

        if {[expr {rand() > $probability(crossover)}]} {
            foreach {offspring1 offspring2} [$Hillclimb::mateProc $parent1 $parent2] {}
            lappend offspring $offspring1 $offspring2
        } else {
            lappend offspring $parent1 $parent2
        }
    }

    return $offspring
}

# GeneticPerm::rouletteMate
#
#	Mate the fittest members of the gene pool using a roulette wheel
#	selection.  The chance of mating to occur is defined by the
#	GeneticPerm::probability(crossover) variable.  This usually has a value
#	from 0.6 to 1.0.  If mating does not occur between 2 selected members
#	then they are carried through unchanged to the next generation.
#
# Arguments:
#
#	genePool	The gene pool that will mate.
#
# Result:
#	A new gene pool.

proc GeneticPerm::rouletteMate {genePool {maxChromosomes -1}} {
    variable probability
    set poolSize [llength $genePool]

    # Sort the gene pool to find the top 50% fittest members.
    set sortedGenePool [lsort -real -decreasing -command GeneticPerm::geneCompare $genePool]
    set totalFitness 0.0
    foreach gene $sortedGenePool {
        set fitness [Hillclimb::scoreKey $gene]
        set totalFitness [expr {$fitness + $totalFitness}]
    }
    set normalFactor [expr {1.0 / $totalFitness}]
    set accumulation 0.0
    foreach gene $sortedGenePool {
        set fitness [Hillclimb::scoreKey $gene]
        set accumulation [expr {$fitness + $accumulation}]
        set normalAccumulation($gene) [expr {$accumulation * $normalFactor}]
    }

    set offspring {}
    for {set i 0} {$i < $poolSize/2} {incr i} {
        set cutoff [expr {rand()}]
        set index1 0
        foreach gene $sortedGenePool {
            if {$normalAccumulation($gene) > $cutoff} {
                break
            }
            incr index1
        }
        set parent1 $gene

        set cutoff [expr {rand()}]
        set index2 0
        foreach gene $sortedGenePool {
            if {$normalAccumulation($gene) > $cutoff} {
                break
            }
            incr index2
        }
        set parent2 $gene
#puts "Mating $index1 with $index2 values $normalAccumulation($parent1) and $normalAccumulation($parent2)"

        # Do we need to prevent hermaphroditic mating?

        if {[expr {rand() > $probability(crossover)}]} {
            foreach {offspring1 offspring2} [$Hillclimb::mateProc $parent1 $parent2 $maxChromosomes] {}
            lappend offspring $offspring1 $offspring2
        } else {
            lappend offspring $parent1 $parent2
        }
    }

    return $offspring
}

# GeneticPerm::mutatePool
#
#	Mutate an entire gene pool.  Mutations normally occur right after
#       mating.  The chance of a mutation occurring to any specific member is
#       defined by the GeneticPerm::probability(mutate) variable.
#
# Arguments:
#
#	genePool	The gene pool that will mutate.
#
# Result:
#	A new gene pool.

proc GeneticPerm::mutatePool {genePool} {
    variable probability
    set newGenePool {}

    foreach gene $genePool {
        if {[expr {rand() > $probability(mutate)}]} {
            lappend newGenePool [mutate $gene $Hillclimb::mutationAmount] 
        } else {
            lappend newGenePool $gene
        }
    }

    return $newGenePool
}

# GeneticPerm::geneCompare
#
#	Comparison procedure for sorting a gene pool based on the fitness
#       of its members.
#
# Arguments:
#
#	gene1   The first gene to compare.
#	gene2   The second gene to compare.
#
# Result:
#	A negative value if the first gene is less fit than the second, 0 if
#       they are both equally fit, or a positive value if the first gene is
#       more fit than the second.

proc GeneticPerm::geneCompare {gene1 gene2} {
    set score1 [Hillclimb::scoreKey $gene1]
    set score2 [Hillclimb::scoreKey $gene2]

    return [expr {int($score1 - $score2)}]
}

proc GeneticPerm::dumpPool {genePool generation} {
    if {[llength $genePool] == 0} {
        puts "Gene pool is empty!"
        return
    }

    set totalFitness 0
    set totalSquareFitness 0
    set sortedGenePool [lsort -real -decreasing -command GeneticPerm::geneCompare $genePool]
    set n [llength $genePool]

    puts "#Total of $n genes"
    foreach gene $sortedGenePool {
        set fitness [Hillclimb::scoreKey $gene]
        set totalFitness [expr {$fitness + $totalFitness}]
        set totalSquareFitness [expr {$fitness*$fitness + $totalSquareFitness}]
        #puts "#$gene (Fit: $fitness)"
    }
    set bestGene [lindex $sortedGenePool 0]
    set worstGene [lindex $sortedGenePool end]

    puts "#Mean fitness:  [expr {$totalFitness / [llength $genePool]}]"
    puts "#Sdev:  [expr {sqrt($n*($totalSquareFitness) - $totalFitness*$totalFitness)/($n*$n)}]"
    puts "#Worst fitness:  $worstGene [Hillclimb::scoreKey $worstGene]"
    puts "#Best fitness:   $bestGene [Hillclimb::scoreKey $bestGene]"
    ::Hillclimb::showFit $bestGene $generation
}

proc GeneticPerm::getBestFit {genePool} {
    set bestFit [lindex [lsort -real -decreasing -command GeneticPerm::geneCompare $genePool] 0]
    set bestVal [Hillclimb::scoreKey $bestFit]

    return [list $bestFit $bestVal]
}
