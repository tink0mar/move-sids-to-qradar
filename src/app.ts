import { getRules, addNewEventMappingAndQidRecord } from "./utils"

function sleep(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms))
}

let i = 0

async function main() {
    const sids = await getRules()

    for (const sid of sids) {
        try {
            await addNewEventMappingAndQidRecord({
                name: sid.name,
                sid: sid.sid,
                severity: sid.severity,
            })
            console.log(sid, "Successfull")
        } catch (e) {
            console.log(sid, "Unsuccessfull")
        }
        i++
    }
}

main()
