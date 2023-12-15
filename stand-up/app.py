import asyncio
import grp
import logging
import psycopg2

from math import log
import grpc

from alert_pb2 import *
from alert_pb2_grpc import *

import config

class Capturer(AlertCapturer):
    async def SendAlert(
        self,
        request: Alert,
        context: grpc.aio.ServicerContext,
        ) -> Result:
            await self.Write(request=request)
            return Result(res_type=Result.RES_OK)
    
    async def ReceiveAlert(
        self,
        request: Empty,
        context: grpc.aio.ServicerContext,
        ):
            try:
                conn = psycopg2.connect(host=config.PG_HOST, dbname=config.PG_DB, user=config.PG_LOGIN, password=config.PG_PASS)
                cursor = conn.cursor()

                insert_query = 'SELECT * FROM alerts;'
                cursor.execute(insert_query)
                for al in cursor.fetchall():
                    print(al)
                    msg = Alert()
                    msg.d_ip = al[3]
                    msg.src_ip = al[2]
                    msg.rule_type = Alert.RULE_ALERT
                    msg.date = "Not Impl"
                    msg.rule_name = al[1]
                    yield msg

            except psycopg2.Error as e:
                logging.error("Error select alert data:", e)

            finally:
                if conn is not None:
                    cursor.close()
                    conn.close()
    
    async def Write(self, request: Alert):
        try:
            conn = psycopg2.connect(host=config.PG_HOST, dbname=config.PG_DB, user=config.PG_LOGIN, password=config.PG_PASS)
            cursor = conn.cursor()

            insert_query = 'INSERT INTO alerts (alert_name, src_ip, dst_ip) VALUES (%s, %s, %s)'
            cursor.execute(insert_query, [request.rule_name, request.src_ip, request.d_ip])
            conn.commit()

        except psycopg2.Error as e:
            logging.error("Error inserting user data:", e)

        finally:
            # Close communication with the database
            if conn is not None:
                cursor.close()
                conn.close()
        
        logging.info(f"Alert: {request.rule_type} from {request.src_ip} to {request.d_ip}")

async def serve():
    server = grpc.aio.server()
    add_AlertCapturerServicer_to_server(Capturer(), server)
    server.add_insecure_port("0.0.0.0:50051")
    logging.info("Server start listening")
    await server.start()
    await server.wait_for_termination()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(serve())