import fs from "fs";
const path="docs/evaluation/unseen-first-pass-10/first-pass-captures";
const installfix={
 report_id:"2a1a6e35-e808-4b4a-b311-3b1d708b32b4",
 report:{title:"InstallFix and Claude Code",source_url:"https://www.trendmicro.com/en_us/research/26/e/installfix-and-claude-code.html"},
 counts:{all:19,indicators:0,pending_actionable:5,status_axes:{generation:"first_pass_recorded",contract_freshness:{status:"current"},classification_uncertainty:{needs_review:5},package_discovery:{status:"pending",declared:1,extracted:0,pending:1}}},
 extraction_quality:{codes:["ai_escalation_unsupported","authoritative_section_empty","malicious_assessed_non_members","linked_ioc_source_not_ingested"]},
 linked_ioc_sources:[{original_url:"https://www.trendmicro.com/content/dam/trendmicro/global/en/research/26/e/installfix/IOCS_InstallFix.txt",lifecycle_status:"discovered",extraction_status:"pending"}],
 candidates:{items:[
  {type:"url",value:"https://download-version.1-5-8.com/claude.msixbundle",is_ioc:true,indicator_membership:false,assessment:"unknown"},
  {type:"sha1",value:"811fbf0ff6b6acabe4b545e493ec0dd0178a0302",is_ioc:true,indicator_membership:false,assessment:"malicious"},
  {type:"sha256",value:"2f04ba77bb841111036b979fc0dab7fcbae99749718ae1dd6fd348d4495b5f74",is_ioc:true,indicator_membership:false,assessment:"malicious"},
  {type:"ip",value:"104.21.0.95",is_ioc:true,indicator_membership:false,assessment:"context_only",match_state:"context_only"},
  {type:"ip",value:"185.177.239.255",is_ioc:true,indicator_membership:false,assessment:"context_only",match_state:"context_only"},
  {type:"ip",value:"77.91.97.244",is_ioc:true,indicator_membership:false,assessment:"context_only",match_state:"context_only"},
  {type:"domain",value:"download-version.1-5-8.com",is_ioc:true,indicator_membership:false,assessment:"malicious"},
  {type:"domain",value:"oakenfjrod.ru",is_ioc:true,indicator_membership:false,assessment:"malicious"},
  {type:"domain",value:"hosted-by.yeezyhost.net",is_ioc:true,indicator_membership:false,assessment:"context_only",match_state:"context_only"},
  {type:"domain",value:"1-5-8.com",is_ioc:true,indicator_membership:false,assessment:"context_only",match_state:"context_only"},
  {type:"domain",value:"get-version.com",is_ioc:true,indicator_membership:false,assessment:"context_only",match_state:"context_only"}
 ]}
};
const kong={
 report_id:"15399bb2-86f5-4cab-94dc-af5818db0192",
 report:{title:"KongTuke ClickFix",source_url:"https://www.trendmicro.com/en_us/research/26/c/kongtuke-clickfix-abuse-of-compromised-wordpress-sites.html"},
 counts:{all:12,indicators:2,pending_actionable:11,status_axes:{generation:"first_pass_recorded",contract_freshness:{status:"current"},classification_uncertainty:{needs_review:9},package_discovery:{status:"pending",declared:1,extracted:0,pending:1}}},
 extraction_quality:{codes:["ai_escalation_unsupported","ai_evidence_ungrounded","authoritative_section_empty","malicious_assessed_non_members","linked_ioc_source_not_ingested"]},
 linked_ioc_sources:[{original_url:"https://www.trendmicro.com/content/dam/trendmicro/global/en/research/26/c/clickfix/MDR-ClickFix-IOC.txt",lifecycle_status:"discovered",extraction_status:"pending"}],
 candidates:{items:[
  {type:"url",value:"https://ainttby.com/6f54.js",is_ioc:true,indicator_membership:true},
  {type:"url",value:"https://ctpsih.com/2d5h.js",is_ioc:true,indicator_membership:true},
  {type:"url",value:"https://foodgefy.com/6o0jk.js",is_ioc:true,indicator_membership:false,assessment:"malicious"},
  {type:"url",value:"http://foodgefy.com/6o0jk.js",is_ioc:true,indicator_membership:false,assessment:"malicious"},
  {type:"url",value:"http://45.61.138.224/n",is_ioc:true,indicator_membership:false,match_state:"needs_review"},
  {type:"url",value:"https://www.dropbox.com/",is_ioc:false,indicator_membership:false,assessment:"context_only",match_state:"context_only"},
  {type:"url",value:"https://www.dropbox.com/scl/fi/np4h0kexqq5r9vlpzwg4d/rp?rlkey=fwg1koexylntccobyxaliju7w&st=3wxzp44k&dl=1",is_ioc:true,indicator_membership:false,match_state:"needs_review"},
  {type:"ip",value:"162.33.178.171",is_ioc:true,indicator_membership:false,assessment:"malicious"},
  {type:"ip",value:"45.61.138.224",is_ioc:true,indicator_membership:false},
  {type:"ip",value:"158.247.252.178",is_ioc:true,indicator_membership:false,assessment:"malicious"},
  {type:"ip",value:"170.168.103.208",is_ioc:true,indicator_membership:false,assessment:"malicious"},
  {type:"ip",value:"149.154.164.13",is_ioc:true,indicator_membership:false,assessment:"malicious"}
 ]}
};
fs.writeFileSync(path+"/trend-installfix.json",JSON.stringify(installfix,null,2));
fs.writeFileSync(path+"/trend-kongtuke.json",JSON.stringify(kong,null,2));
console.log("wrote compact captures");
