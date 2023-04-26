import * as fs from "fs"
import * as readline from "readline"
import axios from "axios"
import https from "https"
import { categories } from "./categories"

const logSourceTypeId = 4001
const logSourceId = 112

interface ISid {
    name: string
    sid: number
    severity: number
}

const file =
    "/home/martin/3BIT/BP/move-sids-to-qradar/rules-for-qradar/malware/Phishing - 6023"
const lowLevelCategory = 6023

export const getRules = async (): Promise<Array<ISid>> => {
    return new Promise((resolve, reject) => {
        let sids: Array<ISid> = []

        const data = fs.readFileSync(`${file}`)

        const rl = readline.createInterface({
            input: fs.createReadStream(`${file}`),
        })

        rl.on("line", (line) => {
            if (true) {
                const matchSid = line.match(/sid:(\d+)[^"]/)
                const matchMsg = line.match(/msg:"([^"]+)"/)
                const matchClass = line.match(/classtype:([^ ]+?);/)

                let category = "category"
                if (matchClass) {
                    category = matchClass[1]
                }

                if (matchMsg && matchSid) {
                    sids.push({
                        name: matchMsg[1],
                        sid: Number(matchSid[1]),
                        severity: Number(
                            categories.find(
                                (item) => item.classtype == category
                            )?.severity
                        ),
                    })
                }
            }
        })
        rl.on("close", () => {
            resolve(sids)
        })
    })
}

export const addNewEventMappingAndQidRecord = async (args: {
    name: string
    sid: number
    severity: number
}) => {
    let severity
    if (args.severity == 1) {
        severity = 9
    } else if (args.severity == 2) {
        severity = 6
    } else if (args.severity == 3) {
        severity = 3
    }

    const agent = new https.Agent({
        rejectUnauthorized: false,
    })
    try {
        const requestQidRecord = await axios.post(
            "https://127.0.0.1:4430/api/data_classification/qid_records",
            {
                log_source_type_id: logSourceTypeId,
                name: args.name,
                description: "",
                severity: severity,
                low_level_category_id: lowLevelCategory,
            },
            {
                headers: {
                    Accept: "application/json",
                    SEC: "c69be11d-a40d-4f40-99ea-a934e55f0da4",
                },
                httpsAgent: agent,
            }
        )

        const requestEventMappings = await axios.post(
            "https://127.0.0.1:4430/api/data_classification/dsm_event_mappings",
            {
                log_source_type_id: logSourceTypeId,
                log_source_event_id: `${args.sid}`,
                log_source_event_category: "Suricata Alert",
                qid_record_id: requestQidRecord.data.id,
            },
            {
                headers: {
                    Accept: "application/json",
                    SEC: "c69be11d-a40d-4f40-99ea-a934e55f0da4",
                },

                httpsAgent: agent,
            }
        )
    } catch (error) {
        throw error
    }
}
