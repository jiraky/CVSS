/**
 * CVSS v2 Java Data Structure 
 * Copyright (c) 2015 - Mattia Zago 
 * <a href="mailto:dev@zagomattia.it">dev@zagomattia.it</a>
 * 
 * NVD Common Vulnerability Scoring System Support v2
 * The Common Vulnerability Scoring System (CVSS) provides an open framework 
 * for communicating the characteristics and impacts of IT vulnerabilities. 
 * CVSS consists of 3 groups: Base, Temporal and Environmental. Each group 
 * produces a numeric score ranging from 0 to 10, and a Vector, a compressed 
 * textual representation that reflects the values used to derive the score. 
 * The Base group represents the intrinsic qualities of a vulnerability. The 
 * Temporal group reflects the characteristics of a vulnerability that change 
 * over time. The Environmental group represents the characteristics of a 
 * vulnerability that are unique to any user's environment. CVSS enables IT 
 * managers, vulnerability bulletin providers, security vendors, application 
 * vendors and researchers to all benefit by adopting this common language of 
 * scoring IT vulnerabilities.
 * 
 * ----------------------------------------------------------------------------
 *                               DISCLAIMER
 * ----------------------------------------------------------------------------
 * This Java library implements the structure of the CVSS v2 standard. All the 
 * relevant information and texts are taken from the NIST documentation 
 * (https://nvd.nist.gov/cvss.cfm) or the FIRST CVSS guide
 * (http://www.first.org/cvss/).
 *
 * ----------------------------------------------------------------------------
 *                                 LICENSE
 * ----------------------------------------------------------------------------
 * The following project is released under BSD 3-Clause License
 *
 * Copyright (c) 2015 - Mattia Zago 
 * <a href="mailto:dev@zagomattia.it">dev@zagomattia.it</a>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the copyright holder nor the names of its 
 *    contributors may be used to endorse or promote products derived from this 
 *    software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 */
package it.zagomattia.cvss;

import it.zagomattia.cvss.base.*;
import it.zagomattia.cvss.temporal.*;
import it.zagomattia.cvss.environmental.*;


/**
 *
 * @author Mattia Zago <a href="mailto:dev@zagomattia.it">dev@zagomattia.it</a>
 */
public class VectorParser {
    
    public static void main(String[] args) {
        CVSSBase b = new CVSSBase(AV.A, AC.H, AU.M, C.C, I.N, A.N);
        System.out.println("b:  "+b.toString()+"\tScore: "+String.format("%1$,.2f", b.score()));
        CVSSBase b1 = parseBaseVector(b.toString());
        System.out.println("b1: "+b1+"\tScore: "+String.format("%1$,.2f", b.score()));
        System.out.println("b equals b1 ? "+(b.equals(b1)?"yes":"no"));
        
        CVSSTemporal t = new CVSSTemporal(b, E.U, RL.OF, RC.UC);
        System.out.println("\nt:  "+t.toString()+"\tScore: "+String.format("%1$,.2f", t.score()));
        CVSSTemporal t1 = parseTemporalVector(t.toStringFull());
        System.out.println("t1: "+t1+"\tScore: "+String.format("%1$,.2f", t.score()));
        System.out.println("\tt:  "+t.toStringFull());
        System.out.println("\tt1: "+t1.toStringFull());
        System.out.println("t equals t1 ? "+(t.equals(t1)?"yes":"no"));
        
        CVSSEnvironmental e = new CVSSEnvironmental(t, CDP.ND, TD.ND, CR.L, IR.L, AR.L);
        System.out.println("\ne:  "+e.toString()+"\tScore: "+String.format("%1$,.2f", e.score()));
        CVSSEnvironmental e1 = parseEnvironmentalVector(e.toStringFull());
        System.out.println("e1: "+e1+"\tScore: "+String.format("%1$,.2f", e.score()));
        System.out.println("\te:  "+e.toStringFull());
        System.out.println("\te1: "+e1.toStringFull());
        System.out.println("e equals e1 ? "+(e.equals(e1)?"yes":"no"));
    }
    
    public static CVSSBase parseBaseVector(String base) throws IllegalArgumentException, NullPointerException{
        
        if(base == null || base.isEmpty()) throw new NullPointerException("Param 'base' cannot be null or empty");
        
        CVSSBase baseScore = new CVSSBase();
        
        //AV:[L,A,N]/AC:[H,M,L]/Au:[M,S,N]/C:[N,P,C]/I:[N,P,C]/A:[N,P,C]
        String[] baseArray = base.split("/");
        for(String b : baseArray) {
            //AV:[L,A,N]
            String[] bArray = b.split(":");
            String vector = bArray[0];
            String value = bArray[1];
            
            switch(vector) {
                case "AV": baseScore.setAccessVector(AV.valueOf(value)); break;
                case "AC": baseScore.setAccessComplexity(AC.valueOf(value)); break;
                case "Au": baseScore.setAuthentication(AU.valueOf(value)); break;
                case "C": baseScore.setConfImpact(C.valueOf(value)); break;
                case "I": baseScore.setIntegImpact(I.valueOf(value)); break;
                case "A": baseScore.setAvailImpact(A.valueOf(value)); break;
                default: throw new NoClassDefFoundError("Class "+vector+" not found");
            }
        }
        return baseScore;        
    }
    
    public static CVSSTemporal parseTemporalVector(String temp) throws IllegalArgumentException, NullPointerException{
        
        if(temp == null || temp.isEmpty()) throw new NullPointerException("Param 'temp' cannot be null or empty");
        
        CVSSTemporal tempScore = new CVSSTemporal();
        
        //E:[U,POC,F,H,ND]/RL:[OF,TF,W,U,ND]/RC:[UC,UR,C,ND]
        String[] tempArray = temp.split("/");
        for(String t : tempArray) {
            //E:[U,POC,F,H,ND]
            String[] tArray = t.split(":");
            String vector = tArray[0];
            String value = tArray[1];
            
            switch(vector) {
                case "E": tempScore.setExploitability(E.valueOf(value)); break;
                case "RL": tempScore.setRemediationLevel(RL.valueOf(value)); break;
                case "RC": tempScore.setReportConfidence(RC.valueOf(value)); break;
                
                case "AV": tempScore.getBaseScore().setAccessVector(AV.valueOf(value)); break;
                case "AC": tempScore.getBaseScore().setAccessComplexity(AC.valueOf(value)); break;
                case "Au": tempScore.getBaseScore().setAuthentication(AU.valueOf(value)); break;
                case "C": tempScore.getBaseScore().setConfImpact(C.valueOf(value)); break;
                case "I": tempScore.getBaseScore().setIntegImpact(I.valueOf(value)); break;
                case "A": tempScore.getBaseScore().setAvailImpact(A.valueOf(value)); break;
                default: throw new NoClassDefFoundError("Class "+vector+" not found");
            }
        }
        return tempScore;        
    }
    
    public static CVSSEnvironmental parseEnvironmentalVector(String env) throws IllegalArgumentException, NullPointerException{
        
        if(env == null || env.isEmpty()) throw new NullPointerException("Param 'env' cannot be null or empty");
        
        CVSSEnvironmental envScore = new CVSSEnvironmental();
        
        //CDP:[N,L,LM,MH,H,ND]/TD:[N,L,M,H,ND]/CR:[L,M,H,ND]/IR:[L,M,H,ND]/AR:[L,M,H,ND]
        String[] envArray = env.split("/");
        for(String e : envArray) {
            //CDP:[N,L,LM,MH,H,ND]
            String[] eArray = e.split(":");
            String vector = eArray[0];
            String value = eArray[1];
            
            switch(vector) {
                case "AR": envScore.setAvailReq(AR.valueOf(value)); break;
                case "CDP": envScore.setCollateralDamagePotential(CDP.valueOf(value)); break;
                case "CR": envScore.setConfReq(CR.valueOf(value)); break;
                case "IR": envScore.setIntegReq(IR.valueOf(value)); break;
                case "TD": envScore.setTargetDistribution(TD.valueOf(value)); break;
                
                case "E": envScore.getTemporalScore().setExploitability(E.valueOf(value)); break;
                case "RL": envScore.getTemporalScore().setRemediationLevel(RL.valueOf(value)); break;
                case "RC": envScore.getTemporalScore().setReportConfidence(RC.valueOf(value)); break;
                
                case "AV": envScore.getTemporalScore().getBaseScore().setAccessVector(AV.valueOf(value)); break;
                case "AC": envScore.getTemporalScore().getBaseScore().setAccessComplexity(AC.valueOf(value)); break;
                case "Au": envScore.getTemporalScore().getBaseScore().setAuthentication(AU.valueOf(value)); break;
                case "C": envScore.getTemporalScore().getBaseScore().setConfImpact(C.valueOf(value)); break;
                case "I": envScore.getTemporalScore().getBaseScore().setIntegImpact(I.valueOf(value)); break;
                case "A": envScore.getTemporalScore().getBaseScore().setAvailImpact(A.valueOf(value)); break;
                default: throw new NoClassDefFoundError("Class "+vector+" not found"); 
            }
        }
        return envScore;        
    }
    
    

}
