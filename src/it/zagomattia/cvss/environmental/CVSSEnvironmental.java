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
package it.zagomattia.cvss.environmental;

import it.zagomattia.cvss.CVSSMetric;
import it.zagomattia.cvss.temporal.CVSSTemporal;

/**
 * Different environments can have an immense bearing on the risk that a 
 * vulnerability poses to an organization and its stakeholders. The CVSS 
 * environmental metric group captures the characteristics of a vulnerability 
 * that are associated with a user's IT environment. Since environmental 
 * metrics are optional they each include a metric value that has no effect 
 * on the score. This value is used when the user feels the particular metric 
 * does not apply and wishes to "skip over" it.
 * @author Mattia Zago <a href="mailto:dev@zagomattia.it">dev@zagomattia.it</a>
 */
public class CVSSEnvironmental implements CVSSMetric {

    private CVSSTemporal TemporalScore;
    private CDP CollateralDamagePotential;
    private TD TargetDistribution;
    private CR ConfReq;
    private IR IntegReq;
    private AR AvailReq;

    public CVSSEnvironmental() {
        this.TemporalScore = new CVSSTemporal();
    }
    
    public CVSSEnvironmental(CVSSTemporal TemporalScore, CDP CollateralDamagePotential, TD TargetDistribution, CR ConfReq, IR IntegReq, AR AvailReq) {
        setTemporalScore(TemporalScore);
        setCollateralDamagePotential(CollateralDamagePotential);
        setTargetDistribution(TargetDistribution);
        setConfReq(ConfReq);
        setIntegReq(IntegReq);
        setAvailReq(AvailReq);
    }
    
    @Override
    public Double score() {
        return  Math.round (
                    10 * // need to round to 1 decimal digit
                    (
                        AdjustedTemporal() + 
                                (10 - AdjustedTemporal()) * 
                                getCollateralDamagePotential().getValue()
                    ) * getTargetDistribution().getValue()
                ) / 10d // need to round to 1 decimal digit
                ;
    }

    private Double AdjustedTemporal() {
        return  Math.round (
                    10 * // need to round to 1 decimal digit
                    AdjustedImpact() * 
                    getTemporalScore().getExploitability().getValue() * 
                    getTemporalScore().getRemediationLevel().getValue() * 
                    getTemporalScore().getReportConfidence().getValue()
                ) / 10d // need to round to 1 decimal digit
                ;
    }
    
    private Double AdjustedImpact() {
        return Math.min(
                10,
                10.41 * (
                        1 - 
                            (1 - getConfReq().getValue()) * 
                            (1 - getIntegReq().getValue()) * 
                            (1 - getAvailReq().getValue())
                        )
        );
    }
    
    @Override
    public String toString() {
        return    "CDP:"+getCollateralDamagePotential()
                + "/TD:"+getTargetDistribution()
                + "/CR:"+getConfReq()
                + "/IR:"+getIntegReq()
                + "/AR:"+getAvailReq()
                + "";
    }
    
    @Override
    public String[] getVectors() {
        return new String[]{"CDP","TD","CR","IR","AR"};
    }
    
    @Override
    public String toStringFull() {
        return getTemporalScore().toStringFull()+"/"+toString();
    }
    
    @Override
    public boolean equals(Object target) {
        if( !(target instanceof CVSSEnvironmental)) return false;
        CVSSEnvironmental t = (CVSSEnvironmental)target;
        if(this.getTemporalScore().equals(t.getTemporalScore()))
            if(this.getAvailReq().equals(t.getAvailReq()))
                if(this.getCollateralDamagePotential().equals(t.getCollateralDamagePotential()))
                    if(this.getConfReq().equals(t.getConfReq()))
                        if(this.getIntegReq().equals(t.getIntegReq()))
                            if(this.getTargetDistribution().equals(t.getTargetDistribution()))
                                return true;
        
        return false;
    }
    
    public CVSSTemporal getTemporalScore() {
        return TemporalScore;
    }

    public final void setTemporalScore(CVSSTemporal TemporalScore) {
        this.TemporalScore = TemporalScore;
    }

    public CDP getCollateralDamagePotential() {
        return CollateralDamagePotential;
    }

    public final void setCollateralDamagePotential(CDP CollateralDamagePotential) {
        this.CollateralDamagePotential = CollateralDamagePotential;
    }

    public TD getTargetDistribution() {
        return TargetDistribution;
    }

    public final void setTargetDistribution(TD TargetDistribution) {
        this.TargetDistribution = TargetDistribution;
    }

    public CR getConfReq() {
        return ConfReq;
    }

    public final void setConfReq(CR ConfReq) {
        this.ConfReq = ConfReq;
    }

    public IR getIntegReq() {
        return IntegReq;
    }

    public final void setIntegReq(IR IntegReq) {
        this.IntegReq = IntegReq;
    }

    public AR getAvailReq() {
        return AvailReq;
    }

    public final void setAvailReq(AR AvailReq) {
        this.AvailReq = AvailReq;
    }
}
