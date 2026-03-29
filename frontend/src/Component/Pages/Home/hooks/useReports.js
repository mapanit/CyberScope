import { useState, useEffect } from 'react';

/**
 * Hook для управления отчетами (Word, TXT и Combined)
 */
export const useReports = () => {
    const [wordReports, setWordReports] = useState([]);
    const [loadingReports, setLoadingReports] = useState(false);
    const [txtReports, setTxtReports] = useState({});
    const [loadingTxtReports, setLoadingTxtReports] = useState(false);
    const [combinedReports, setCombinedReports] = useState({ json: [], txt: [], word: [] });
    const [loadingCombined, setLoadingCombined] = useState(false);
    const [combinedReportFilter, setCombinedReportFilter] = useState('all');

    const fetchWordReports = async () => {
        setLoadingReports(true);
        try {
            const response = await fetch('http://localhost:8000/api/word-reports');
            const data = await response.json();
            if (data.status === 'success') {
                setWordReports(data.reports);
            }
        } catch (error) {
            console.error('Ошибка при загрузке списка отчетов:', error);
        } finally {
            setLoadingReports(false);
        }
    };

    const fetchCombinedReports = async () => {
        setLoadingCombined(true);
        try {
            const response = await fetch('http://localhost:8000/api/combined-reports');
            const data = await response.json();
            if (data.status === 'success') {
                setCombinedReports({
                    json: data.json_reports || [],
                    txt: data.txt_reports || [],
                    word: data.word_reports || []
                });
            }
        } catch (error) {
            console.error('Ошибка при загрузке скомпилированных отчетов:', error);
        } finally {
            setLoadingCombined(false);
        }
    };

    const fetchTxtReports = async () => {
        setLoadingTxtReports(true);
        try {
            const response = await fetch('http://localhost:8000/api/txt-reports');
            const data = await response.json();
            if (data.status === 'success') {
                setTxtReports(data.reports || {});
            }
        } catch (error) {
            console.error('Ошибка при загрузке txt отчетов:', error);
        } finally {
            setLoadingTxtReports(false);
        }
    };

    useEffect(() => {
        fetchWordReports();
        fetchCombinedReports();
        fetchTxtReports();
    }, []);

    return {
        wordReports, setWordReports,
        loadingReports, setLoadingReports,
        txtReports, setTxtReports,
        loadingTxtReports, setLoadingTxtReports,
        combinedReports, setCombinedReports,
        loadingCombined, setLoadingCombined,
        combinedReportFilter, setCombinedReportFilter,
        fetchWordReports, fetchCombinedReports, fetchTxtReports
    };
};
