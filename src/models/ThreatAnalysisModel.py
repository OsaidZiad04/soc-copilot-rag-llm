from .BaseDataModel import BaseDataModel
from .db_schemes import ThreatAnalysis
from sqlalchemy.future import select
from sqlalchemy import func
import uuid


class ThreatAnalysisModel(BaseDataModel):

    def __init__(self, db_client: object):
        super().__init__(db_client=db_client)
        self.db_client = db_client

    @classmethod
    async def create_instance(cls, db_client: object):
        instance = cls(db_client)
        return instance

    async def create_analysis(self, analysis: ThreatAnalysis):

        async with self.db_client() as session:
            async with session.begin():
                session.add(analysis)
            await session.commit()
            await session.refresh(analysis)

        return analysis

    async def get_analysis_by_uuid(self, analysis_uuid: str):

        try:
            analysis_uuid = uuid.UUID(str(analysis_uuid))
        except Exception:
            return None

        async with self.db_client() as session:
            stmt = select(ThreatAnalysis).where(ThreatAnalysis.analysis_uuid == analysis_uuid)
            result = await session.execute(stmt)
            record = result.scalar_one_or_none()

        return record

    async def get_all_analyses(self, page: int = 1, page_size: int = 10,
                               risk_level: str = None, input_type: str = None):

        filters = []
        if risk_level:
            filters.append(ThreatAnalysis.risk_level == risk_level)

        if input_type:
            filters.append(ThreatAnalysis.input_type == input_type)

        async with self.db_client() as session:
            count_stmt = select(func.count(ThreatAnalysis.analysis_id))
            if len(filters):
                count_stmt = count_stmt.where(*filters)

            total = (await session.execute(count_stmt)).scalar() or 0

            total_pages = total // page_size
            if total % page_size > 0:
                total_pages += 1

            query = select(ThreatAnalysis)
            if len(filters):
                query = query.where(*filters)

            query = query.order_by(ThreatAnalysis.analysis_id.desc()).offset((page - 1) * page_size).limit(page_size)
            result = await session.execute(query)
            records = result.scalars().all()

        return records, total_pages, total

    async def update_analyst_feedback(self, analysis_uuid: str, feedback: str, notes: str = None):

        try:
            analysis_uuid = uuid.UUID(str(analysis_uuid))
        except Exception:
            return None

        async with self.db_client() as session:
            stmt = select(ThreatAnalysis).where(ThreatAnalysis.analysis_uuid == analysis_uuid)
            result = await session.execute(stmt)
            record = result.scalar_one_or_none()

            if record is None:
                return None

            record.analyst_feedback = feedback
            record.analyst_notes = notes

            await session.commit()
            await session.refresh(record)

        return record

    async def get_stats(self):

        async with self.db_client() as session:
            total = (await session.execute(select(func.count(ThreatAnalysis.analysis_id)))).scalar() or 0

            by_risk_level_query = select(
                ThreatAnalysis.risk_level,
                func.count(ThreatAnalysis.analysis_id)
            ).group_by(ThreatAnalysis.risk_level)

            results = await session.execute(by_risk_level_query)
            by_risk_level = {
                risk_level: count
                for risk_level, count in results.fetchall()
            }

        return {
            "total": total,
            "by_risk_level": by_risk_level
        }
